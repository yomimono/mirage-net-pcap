(*                                                                              
 * Copyright (c) 2015 Mindy Preston <meetup@yomimono.org>                  
 *                                                                              
 * Permission to use, copy, modify, and distribute this software for any        
 * purpose with or without fee is hereby granted, provided that the above       
 * copyright notice and this permission notice appear in all copies.            
 *                                                                              
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES     
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF             
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR      
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
 * DAMAGES       
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN        
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF      
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.               
 *)     

module Make 
    (FS: V1_LWT.FS with type page_aligned_buffer = Cstruct.t) 
    (T: V1_LWT.TIME) 
    (Clock: V1.CLOCK) = struct
  type 'a io = 'a Lwt.t
  type page_aligned_buffer = Cstruct.t
  type buffer = Cstruct.t
  type macaddr = Macaddr.t
  type error = [ `Unimplemented
               | `Disconnected
               | `Unknown of string ]

  type read_result = [
      `Ok of page_aligned_buffer list
    | `Error of FS.error
  ]

  type stats = {
    mutable rx_bytes : int64;
    mutable rx_pkts : int32;
    mutable tx_bytes : int64;
    mutable tx_pkts : int32;
  }

  type id = {
    timing : float option;
    read : string;
    write : string;
    source : FS.t;
    mac : Macaddr.t;
  }

  type t = {
    source : id;
    read_seek : int;
    mutable write_seek : int; (* boooooo *)
    last_read : float option;
    stats : stats;
    pcap_writer: (module Pcap_write.Pcap_writer
                   with type error = FS.error and type fs = FS.t);
    pcap_reader: (module Pcap.HDR)
  }

  let translate_error = function
    | `Not_a_directory s -> `Unknown ("Not a directory: " ^ s)
    | `Is_a_directory s -> `Unknown ("Is a directory: " ^ s)
    | `Directory_not_empty s -> `Unknown ("Directory not empty: " ^ s)
    | `No_directory_entry (_, file) -> `Unknown ("Could not find: " ^ file)
    | `File_already_exists s -> `Unknown ("File already exists: " ^ s)
    | `No_space -> `Unknown "No space"
    | `Format_not_recognised s -> `Unknown ("Format not recognised: " ^s)
    | `Unknown_error s -> `Unknown s
    | `Block_device _ -> `Unknown "Block device error"

  let string_of_error = function
    | `Unknown s -> "Unknown error: " ^ s
    | `Disconnected -> "Disconnected"
    | `Unimplemented -> "Unimplemented"

  let reset_stats_counters t = ()
  let get_stats_counters t = t.stats
  let empty_stats_counter = {
    rx_bytes = 0L;
    rx_pkts = 0l;
    tx_bytes = 0L;
    tx_pkts = 0l;
  }

  let string_of_t t =
    Printf.sprintf "source is file %s, sink is file %s, we're at read position %s" 
      t.source.read t.source.write (string_of_int t.read_seek)

  let mac t = t.source.mac

  let id_of_desc ?timing ~mac ~source ~read ~write =
    match timing with
    | Some f -> { timing = f; source; read; write; mac }
    | None -> { timing = Some 1.0; source; read; write; mac}

  let id t = t.source
  let connect (i : id) =
    let open Lwt in
    FS.stat i.source i.write >>= function
    (* refuse to overwrite a file that already exists *)
    | `Ok _ -> Lwt.return (`Error (`Unknown "requested write file exists"))
    | `Error _ ->
      (* either not present or writes will fail for a reason we'll later
         discover, so go on with it *)
      FS.read i.source i.read 0 (Pcap.sizeof_pcap_header) >>= function
      | `Error p -> Lwt.return (`Error (translate_error p))
      | `Ok [] -> Lwt.return (`Error (`Unknown "empty file could not be parsed"))
      (* complete header should fit easily in the first page for any reasonable
         page size, so only consider the first page when attempting to establish
         the parser *)
      | `Ok (hd :: _) ->
        match Pcap.detect hd with
        | None -> Lwt.return (`Error (`Unknown "file could not be parsed"))
        | Some pcap_impl ->
          let module Reader = (val pcap_impl) in
          let module Writer = Pcap_write.Make (Reader) (FS) in
          Writer.create_pcap_file i.source i.write >>= function
          | `Error p -> Lwt.return (`Error (translate_error p))
          (* by opening the read file first, we can punt on endianness, version,
             etc  and just use the ones we detected in the source file, since
             these aren't provided by ocap afaict *)
          | `Ok () ->
            Lwt.return (`Ok {
                source = i;
                read_seek = Pcap.sizeof_pcap_header;
                write_seek = Pcap.sizeof_pcap_header;
                last_read = None;
                stats = empty_stats_counter;
                pcap_writer = (module Writer);
                pcap_reader = (module Reader);
              })

  let disconnect t =
    Lwt.return_unit

  (* is the expected semantics of writev that each packet will be in its own
       cstruct?  since we don't deal with jumbo frames, it's unlikely that there
       are packets *bigger* than a page, which probably already don't work on
       other backends *)
  let write t buf = 
    let (>>=) = Lwt.bind in
    let module W = (val t.pcap_writer) in
    (* TODO: buf might be >1 page :( *)
    (* things supplied to write are not necessarily page-aligned *)
    let page = Io_page.get 1 in
    let header = Io_page.to_cstruct page in
    let fs, file = t.source.source, t.source.write in
    W.append_packet_to_file fs file t.write_seek (Clock.time ()) header
    >>= function
    | `Error p -> Lwt.return_unit (* TODO: something less broken *)
    | `Ok bytes_written ->
      t.write_seek <- t.write_seek + bytes_written;
      Lwt.return_unit

  let writev t bufs = 
    Lwt.join (List.map (write t) bufs)

  let advance_read_seek t read_seek = { t with read_seek = (t.read_seek + read_seek); }

  let set_last_read t last_read =
    { t with last_read = last_read; }

  (* merge bufs into one big cstruct. *)
  let combine_cstructs l =
    match l with
    | hd :: [] -> hd
    | _ ->
      let consolidated = Cstruct.create (Cstruct.lenv l) in
      let fill read_seek buf =
        Cstruct.blit buf 0 consolidated read_seek (Cstruct.len buf);
        read_seek + (Cstruct.len buf)
      in
      ignore (List.fold_left fill 0 l);
      consolidated

  let rec listen t cb =
    let open Lwt in
    let read_wrapper (i : id) read_seek how_many =
      FS.read i.source i.read read_seek how_many >>= function
      | `Ok [] -> Lwt.return None
      | `Ok (buf :: []) -> Lwt.return (Some (Cstruct.sub buf 0 how_many))
      | `Ok bufs -> Lwt.return (Some (combine_cstructs bufs))
      | `Error _ -> raise (Invalid_argument "Read failed")
    in
    let next_packet t =
      read_wrapper t.source t.read_seek Pcap.sizeof_pcap_packet >>=
      function
      | None -> Lwt.return None
      | Some packet_header ->
        let t = advance_read_seek t Pcap.sizeof_pcap_packet in
        (* try to read packet body *)
        let module R = (val t.pcap_reader) in
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
        read_wrapper t.source t.read_seek packet_size >>= function
        | None -> Lwt.return None
        | Some packet_body ->
          let t = advance_read_seek t (packet_size) in
          return (Some (t, delay, packet_body))
    in
    next_packet t >>= function
    | None -> Lwt.return_unit
    | Some (next_t, delay, packet) ->
      T.sleep delay >>= fun () ->
      cb packet >>= fun () ->
      listen next_t cb

end
