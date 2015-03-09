module Netif (K: V1_LWT.KV_RO) (T: V1_LWT.TIME) = struct

  type 'a io = 'a Lwt.t
  type page_aligned_buffer = Cstruct.t
  type buffer = Cstruct.t
  type macaddr = Macaddr.t
  type error = [ `Unimplemented 
               | `Disconnected 
               | `Unknown of string ]

  type read_result = [
      `Ok of page_aligned_buffer list
    | `Error of K.error
  ]

  type stats = {
    mutable rx_bytes : int64;
    mutable rx_pkts : int32;
    mutable tx_bytes : int64;
    mutable tx_pkts : int32; 
  }

  type id = {
    source : K.t;
    file : string; 
  }

  type t = {
    source : id; (* should really be something like an fd *) 
    seek : int option; (* None for EOF *)
    last_read : float option;
    stats : stats;
    reader : (module Pcap.HDR);
  }

  let reset_stats_counters t = ()
  let get_stats_counters t = t.stats
  let empty_stats_counter = {
    rx_bytes = 0L;
    rx_pkts = 0l;
    tx_bytes = 0L;
    tx_pkts = 0l; 
  }

  let string_of_t t =
    let explicate = function
      | None -> "EOF"
      | Some k -> string_of_int k
    in
    Printf.sprintf "source is file %s; we're at position %s" t.source.file
      (explicate t.seek)

  let id_of_desc ~source ~read = { source; file = read; }

  let id t = t.source 
  let connect (i : id) = 
    Lwt.bind (K.read i.source i.file 0 (Pcap.sizeof_pcap_header)) (
    fun result ->
    match result with 
    | `Error _ -> Lwt.return (`Error (`Unknown "file could not be read") ) 
    | `Ok (bufs : K.page_aligned_buffer list) ->  (* huh, apparently this can return us an empty list? *)
      match bufs with
      | [] -> Lwt.return (`Error (`Unknown "empty file"))
      | hd :: _ ->
        (* hopefully we have a pcap header in bufs *)
        match Pcap.detect hd with
        | None -> Lwt.return (`Error (`Unknown "file could not be parsed"))
        | Some reader ->
          Lwt.return (`Ok { 
              source = i;
              seek = Some Pcap.sizeof_pcap_header;
              last_read = None;
              stats = empty_stats_counter;
              reader;
            })

    )

  let disconnect t = 
    Lwt.return_unit

  (* writes go down the memory hole *)
  let writev t bufs = Printf.printf "packet written\n"; Cstruct.hexdump (List.hd
                                                                           bufs); Lwt.return_unit
  let write t buf = writev t [buf]

  let eof t = { t with seek = None; }

  let advance_seek t seek =
    match t.seek with
    | None -> t
    | Some prev_seek -> { t with seek = Some (prev_seek + seek); }

  let set_last_read t last_read = 
    { t with last_read = last_read; }

  (* merge bufs into one big cstruct. *)
  let combine_cstructs l = 
    match l with
    | hd :: [] -> hd
    | _ -> 
      let consolidated = Cstruct.create (Cstruct.lenv l) in
      let fill seek buf =
        Cstruct.blit buf 0 consolidated seek (Cstruct.len buf);
        seek + (Cstruct.len buf)
      in
      ignore (List.fold_left fill 0 l);
      consolidated

  let rec listen t cb = 
    let open Lwt in 
    let read_wrapper (i : id) seek how_many =
      K.read i.source i.file seek how_many >>= function
      | `Ok [] -> raise (Invalid_argument 
                           (Printf.sprintf "read an empty list, requested %d
                           from %d" how_many seek))
      | `Ok bufs -> return bufs
      | `Error _ -> raise (Invalid_argument "Read failed")
    in
    match t.seek with
    | None -> raise (Invalid_argument "Read after EOF")
    | Some seek_pointer -> 
      let next_packet t =
        read_wrapper t.source seek_pointer Pcap.sizeof_pcap_packet 
        >>= function 
        | [] -> Lwt.return None
        | packet_header :: [] ->
          if (Cstruct.len packet_header) < Pcap.sizeof_pcap_packet then begin
            Lwt.return None
          end
          else begin
            let t = advance_seek t Pcap.sizeof_pcap_packet in
            (* try to read packet body *)
            let module R = (val t.reader : Pcap.HDR) in
            let packet_size = Int32.to_int (R.get_pcap_packet_incl_len
                                              packet_header) in
            let packet_secs = R.get_pcap_packet_ts_sec packet_header in
            let packet_usecs = R.get_pcap_packet_ts_usec packet_header in
            let (t, delay) = 
              let pack (secs, usecs) = 
                let secs_of_usecs = (1.0 /. 1000000.0) in
                (float_of_int (Int32.to_int secs)) +. 
                ((float_of_int (Int32.to_int usecs)) *. secs_of_usecs)
              in
              let this_time = pack (packet_secs, packet_usecs) in
              match t.last_read with
              | None -> (set_last_read t (Some this_time), 0.0) 
              | Some last_time ->
                (set_last_read t (Some this_time)), (this_time -. last_time)
            in
            read_wrapper t.source (seek_pointer + Pcap.sizeof_pcap_packet) packet_size >>= fun packet_bodyv ->
            let packet_body = combine_cstructs packet_bodyv in
            let t = advance_seek t (packet_size) in
            return (Some (t, delay, packet_body))
          end
        | packet_header :: more ->
          raise (Invalid_argument "multipage packet header -- how small are your
                   pages?")
      in
      next_packet t >>= function
      | None -> Lwt.return_unit
      | Some (t, delay, packet) -> 
        T.sleep delay >>= fun () -> 
        cb packet >>= fun () -> 
        listen t cb

  let mac t = Macaddr.broadcast (* arbitrarily *)

end
