open Lwt
(* create_file_header: 
   throws exc for too small a buffer,
   writes something nonzero to a not-too-small buffer,
   feeding created cstruct to Pcap.detect gives us Some mod and not None 
*)

(* need to do necessary contortions to get a Pcap_writer *)
let exn_too_small () =
  let module Reader : Pcap.HDR = Pcap.BE in (*
  FS_unix.connect "test/write" >>= function
  | `Error e -> OUnit.assert_failure ("couldn't make test file: " ^
                                      FS_unix.string_of_error e)
  | `Ok file ->  *)
  let module Writer = Pcap_write.Make(Reader)(FS_unix) in
  (* TODO: try assert_raises with generic string; this is brittle *)
  let expected_str = "invalid bounds (index 0, length 4)" in
  OUnit.assert_raises (Invalid_argument expected_str) (fun () -> Writer.create_file_header
                                                           (Cstruct.create 3));
  Lwt.return_unit


(* create_packet_header: 
   throws exc for too small a buffer,
   writes something nonzero to a not-too-small buffer 
*)

(* create_pcap_file: 
   invalid write cases return the errors we expect 
   (i.e., is a directory, isn't writeable, etc)
   created file is not empty
   created file is readable
   created file contains a readable pcap file header 
   created file contains a readable pcap file header with the correct endianness
*)

(* append_packet_to_file:
   what are the correct semantics for a zero-length packet?  
   (we need to do better on this generally in mirage;
   in lots of places, we'll blow up if we receive a packet with valid headers 
   that encapsulates nothing)
   if we request a write of >65535, it's truncated
   if we request a write of >1 page size, it all gets written (superjumbo
   frames)
   written packets have the requested time
   written packets have the correct snaplen
   written packets, if truncated, have the correct origlen
   attempting to write to a file that hasn't been "initialized" fails
      (support for appends?)
   attempting to write when the FS is full results in an error (is this
   possible?)
*)

let lwt_run f () = Lwt_main.run (f ())

let () =
  let create_file_header = [
    "exn_too_small", `Quick, lwt_run exn_too_small;
  ] in
  let create_packet_header = [

  ] in
  let create_pcap_file = [

  ] in
  let append_packet_to_file = [

  ] in
  Alcotest.run "Pcap_writer" [
    "create_file_header", create_file_header;
    "create_packet_header", create_packet_header;
    "create_pcap_file", create_pcap_file;
    "append_packet_to_file", append_packet_to_file;
  ]
