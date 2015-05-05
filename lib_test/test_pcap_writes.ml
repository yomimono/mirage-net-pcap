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

let file_header_exn_too_small () =
  let module Writer = Pcap_write.Make(Pcap.BE)(FS_unix) in
  let check_with_length length =
    (* slightly convoluted code, since we can't OUnit.assert_raises a generic
       Invalid_argument (doing so will only match if we get the error string
       right) *)
    match (try Some (Writer.create_file_header (Cstruct.create length))
      with Invalid_argument _ -> None)
    with
    | Some () -> OUnit.assert_failure 
                  "Claimed success in writing to a buffer that is too small to contain the full file header"
    | None -> () (* we correctly raised an exception *)
                        
  in
  List.iter check_with_length [0;23];
  Lwt.return_unit

let file_header_sensible_readback () =
  let module Writer = Pcap_write.Make(Pcap.BE)(FS_unix) in
  let header = Cstruct.create 24 in
  let header = zero_cstruct header in
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
   writes something nonzero to a not-too-small buffer,
   time value written in header reflects what was requested in args
   if we request a write of >=65535, snaplen is 65535 and origlen is what we
   requested
   if we request a write of <65535, snaplen = origlen = requested length
*)
let packet_header_exn_too_small () =
  let module Writer = Pcap_write.Make(Pcap.BE)(FS_unix) in
  let check_with_length length =
    match (try Some (Writer.create_packet_header (Cstruct.create length) 0.1 40)
      with Invalid_argument _ -> None)
    with
    | Some () -> OUnit.assert_failure 
                   "Claimed success in writing to a buffer that is too small to contain the full file header"
    | None -> ()
  in
  List.iter check_with_length [0; 15];
  Lwt.return_unit

let packet_header_correct_values () =
  let printer p = string_of_int (Int32.to_int p) in
  let module Writer = Pcap_write.Make(Pcap.BE)(FS_unix) in
  let header = Cstruct.create 16 in
  let header = zero_cstruct header in
  Writer.create_packet_header header 1.3 4096;
  OUnit.assert_equal ~printer 1l (Pcap.BE.get_pcap_packet_ts_sec header);
  OUnit.assert_equal ~printer 300000l (Pcap.BE.get_pcap_packet_ts_usec header);
  OUnit.assert_equal ~printer 4096l (Pcap.BE.get_pcap_packet_incl_len header);
  OUnit.assert_equal ~printer 4096l (Pcap.BE.get_pcap_packet_orig_len header);
  Lwt.return_unit

let packet_header_correct_big_packet () =
  let module Writer = Pcap_write.Make(Pcap.BE)(FS_unix) in
  let header = Cstruct.create 16 in
  let header = zero_cstruct header in
  Writer.create_packet_header header 1.2 65536;
  OUnit.assert_equal 65535l (Pcap.BE.get_pcap_packet_incl_len header);
  OUnit.assert_equal 65536l (Pcap.BE.get_pcap_packet_orig_len header);
  Lwt.return_unit

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
   if we request a write of >1 page size, it all gets written (superjumbo
   frames)
   written packets have the requested time
   written packets have the correct snaplen
   attempting to write to a file that hasn't been "initialized" fails
      (support for appends?)
   attempting to write when the FS is full results in an error (is this
   possible?)
*)

let lwt_run f () = Lwt_main.run (f ())

let () =
  let create_file_header = [
    "file_header_exn_too_small", `Quick, lwt_run file_header_exn_too_small;
    "file_header_sensible_readback", `Quick, lwt_run file_header_sensible_readback
  ] in
  let create_packet_header = [
    "packet_header_exn_too_small", `Quick, lwt_run packet_header_exn_too_small;
    "packet_header_correct_values", `Quick, lwt_run packet_header_correct_values;
    "packet_header_correct_big_packet", `Quick, lwt_run packet_header_correct_big_packet;
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
