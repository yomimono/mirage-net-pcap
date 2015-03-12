module Make (K: V1_LWT.KV_RO) (T: V1_LWT.TIME) = struct
  type 'a io = 'a Lwt.t
  type page_aligned_buffer = Io_page.t
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
    timing : float option;
    source : K.t;
    file : string;
  }

  type t = {
    source : id; (* should really be something like an fd *)
    seek : int;
    last_read : float option;
    stats : stats;
    reader : (module Pcap.HDR);
    written : Cstruct.t list ref;
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
    let explicate k = string_of_int k in
    Printf.sprintf "source is file %s; we're at position %s" t.source.file
      (explicate t.seek)

  let id_of_desc ?timing ~source ~read = match timing with
    | Some f -> { timing = f; source; file = read; }
    | None -> { timing = Some 1.0; source; file = read; }

  let id t = t.source
  let connect (i : id) =
    let open Lwt in
    K.read i.source i.file 0 (Pcap.sizeof_pcap_header) >>=
    fun result ->
    match result with
    | `Error _ -> Lwt.return (`Error (`Unknown "file could not be read") )
    | `Ok bufs ->
      match bufs with
      | [] -> Lwt.return (`Error (`Unknown "empty file"))
      | hd :: _ ->
        (* hopefully we have a pcap header in bufs *)
        match Pcap.detect hd with
        | None -> Lwt.return (`Error (`Unknown "file could not be parsed"))
        | Some reader ->
          Lwt.return (`Ok {
              source = i;
              seek = Pcap.sizeof_pcap_header;
              last_read = None;
              stats = empty_stats_counter;
              reader;
              written = ref [];
            })

  let disconnect t =
    Lwt.return_unit

  let writev t bufs = t.written := t.!written @ bufs; Lwt.return_unit
  let write t buf = writev t [buf]

  let get_written t = t.!written

  let advance_seek t seek = { t with seek = (t.seek + seek); }

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
      | `Ok [] -> Lwt.return None
      | `Ok (buf :: []) -> Lwt.return (Some (Cstruct.sub buf 0 how_many))
      | `Ok bufs -> Lwt.return (Some (combine_cstructs bufs))
      | `Error _ -> raise (Invalid_argument "Read failed")
    in
    let next_packet t =
      read_wrapper t.source t.seek Pcap.sizeof_pcap_packet >>=
      function
      | None -> Lwt.return None
      | Some packet_header ->
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
            match t.source.timing with
            | None -> (set_last_read t (Some this_time), 0.0)
            | Some timing ->
            (set_last_read t (Some this_time)), ((this_time -. last_time) *.
                                                 timing)
        in
        read_wrapper t.source t.seek packet_size >>= function
        | None -> Lwt.return None
        | Some packet_body ->
          let t = advance_seek t (packet_size) in
          return (Some (t, delay, packet_body))
    in
    next_packet t >>= function
    | None -> Lwt.return_unit
    | Some (next_t, delay, packet) ->
      T.sleep delay >>= fun () ->
      cb packet >>= fun () ->
      listen next_t cb

  let mac t = Macaddr.broadcast (* arbitrarily *)

end
