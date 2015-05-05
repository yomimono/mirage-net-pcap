open Lwt
(* create_file_header: 
   throws exc for too small a buffer,
   writes something nonzero to a not-too-small buffer,
   feeding created cstruct to Pcap.detect gives us Some mod and not None 
*)

let zero_cstruct cs =
  let zero c = Cstruct.set_char c 0 '\000' in
  let i = Cstruct.iter (fun c -> Some 1) zero cs in
  Cstruct.fold (fun b a -> b) i cs

(* need to do necessary contortions to get a Pcap_writer *)
let exn_too_small () =
  let module Writer = Pcap_write.Make(Pcap.BE)(FS_unix) in
  let check_with_length length =
    (* slightly convoluted code, since we can't OUnit.assert_raises a generic
       Invalid_argument; we'll only match if we get the error string right *)
    match (try Some (Writer.create_file_header (Cstruct.create length))
      with | Invalid_argument _ -> None)
    with
    | Some () -> OUnit.assert_failure 
                  "Claimed success in writing to a buffer that is too small to contain the full file header"
    | None -> () (* we correctly raised an exception *)
                        
  in
  List.iter check_with_length [0;23];
  Lwt.return_unit

let big_enough_gets_sensible_header () =
  let module Writer = Pcap_write.Make(Pcap.BE)(FS_unix) in
  let header = Cstruct.create 24 in
  zero_cstruct header;
  Writer.create_file_header header;
  (* check first field and last field *)
  OUnit.assert_equal (Pcap.magic_number) (Pcap.BE.get_pcap_header_magic_number header);
  OUnit.assert_equal (Some Pcap.Network.Ethernet)
    (Pcap.Network.of_int32 (Pcap.BE.get_pcap_header_network header));
  (* "valid enough" if a reader can be inferred from the header *)
  match Pcap.detect header with
  | Some inferred_reader -> Lwt.return_unit
  | None -> OUnit.assert_failure "Couldn't infer a reader from a file header we
              wrote ourselves"

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
    "big_enough_gets_sensible_header", `Quick, lwt_run big_enough_gets_sensible_header
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
