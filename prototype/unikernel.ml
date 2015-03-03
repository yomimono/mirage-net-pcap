open V1_LWT
open Lwt

module Reading_netif (K: KV_RO) : sig
  include V1.NETWORK
    with type 'a io = 'a Lwt.t
     and type page_aligned_buffer = Cstruct.t
     and type buffer = Cstruct.t
     and type id = string
     and type macaddr = string

end = struct
  type 'a io = 'a Lwt.t
  type page_aligned_buffer = Cstruct.t
  type buffer = Cstruct.t
  type id = string
  type macaddr = string

  type error = [ `Unimplemented | `Disconnected | `Unknown of string ]

  type stats = {
    mutable rx_bytes : int64;
    mutable rx_pkts : int32;
    mutable tx_bytes : int64;
    mutable tx_pkts : int32; 
  }

  type t = {
    source : string; (* should really be something like an fd *) 
    mutable seek : int; (* probably shouldn't actually limit size *)
    stats : stats;
  }

  (* TODO: stats *)
  let reset_stats_counters t = ()
  let get_stats_counters t = t.stats

  let id t = t.source 
  let connect id = Lwt.return (`Error (`Unimplemented)) 
  let disconnect _ = Lwt.return_unit

  let write t buf = Lwt.return_unit
  let writev t bufs = Lwt.return_unit

  let listen t cb = Lwt.return_unit
  let mac t = t.source

end

module Main (C: CONSOLE) (K: KV_RO) (N: NETWORK) = struct
  (* thing to do is probably try to read the amount of data that we know is in a
    pcap file header to start off, 
    then as we go on,
    try to read the amount of data that we know is in the header for each packet,
     and based on that, read the relevant amount of information and return it *)
  (* that's kind of what `packets` does, of course, but it would be really nice
     to get it as an Lwt_stream instead of a Cstruct.iter, and also not have to
     pass the entire buffer at once -- I think that's what I was getting at with
     this comment.  Since packets expects *not* to see the whole file-level
     header, it should be possible to just keep getting new sequences until EOF *)
  let enqueue_packets packet_seq =
    let (queue, push) = Lwt_stream.create () in
    let () = Cstruct.fold (fun _ packet -> push (Some packet)) packet_seq () in
    let () = push None in (* EOF *)
    queue
  (* What is this buying us?  The ability to make something more complicated
     than what we can express in a `fold`, I guess.  And I think we do need that
     for our pseudonetif. *)

  let start c k n =
    (* TODO: will need a better strategy for reading large pcaps *)
    let chunk_size = 1024000 in
    let file = "mirage_dhcp_discover.pcap" in
    K.read k file 0 chunk_size >>= fun result -> 
    match result with
    | `Error _ -> 
      C.log c (Printf.sprintf "I know of no file called %s \n" file);
      Lwt.return_unit
    | `Ok bufs -> 
      (* merge bufs into one big cstruct.  TODO: This isn't really a 
         nice way to do this. *)
      let condensed = Cstruct.of_string (Cstruct.copyv bufs) in
      let buflen = Cstruct.lenv bufs in
      C.log c (Printf.sprintf "got %d bytes from file %s and stuck them in
      something %d long" buflen file (Cstruct.len condensed));
      match Pcap.detect condensed with
      | Some reader ->
        let module R = (val reader : Pcap.HDR) in
        let pausing_reader l (packet_header, packet_body) =
          let packet_secs = R.get_pcap_packet_ts_sec packet_header in
          let packet_usecs = R.get_pcap_packet_ts_usec packet_header in
          l >>= fun last_time ->
          let how_long = 
            match last_time with
            | None -> 0.0
            | Some (last_secs, last_usecs) -> 
              let pack (secs, usecs) =
                let secs_of_usecs = (1.0 /. 10000000.0) in
                (float_of_int (Int32.to_int secs)) +.  
                ((float_of_int (Int32.to_int usecs)) *. secs_of_usecs) 
              in
              let this_time = pack (packet_secs, packet_usecs) in
              this_time -. (pack (last_secs, last_usecs))
          in
          C.log c (Printf.sprintf "Waiting %f\n" how_long);
          OS.Time.sleep how_long >>= 
          fun () -> 
          N.write n packet_body >>= fun () -> 
          return (Some (packet_secs, packet_usecs))
        in
        (* Pcap.packets expects to be called on the Pcap file body and will
           choke if exposed to the file-level header *)
        let pcap_body = Cstruct.shift condensed Pcap.sizeof_pcap_header in
        let packet_seq = Pcap.packets reader pcap_body in
        C.log_s c "got a packet sequence..." >>= fun () ->
        (* Cstruct.fold parrot packet_seq (Lwt.return_unit) *)
        Cstruct.fold pausing_reader packet_seq (Lwt.return None) >>=
        fun _ -> Lwt.return_unit
      | None -> C.log c (Printf.sprintf "Couldn't figure out how to treat %s as
                           a valid pcap file\n" file); Lwt.return_unit
end
