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

let or_fail = function
  | `Error e -> OUnit.assert_failure (FS_unix.string_of_error e)
  | `Ok q -> Lwt.return q

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
   invalid write cases return the errors we expect (i.e., is a directory, isn't writeable, etc)
   created file is not empty
   created file is readable
   created file contains a readable pcap file header 
   created file contains a readable pcap file header with the correct endianness
*)

(* using some stub FS implementations that always return errors,
   verify that Pcap_write.create_pcap_file 
   always passes underlying FS errors up to the caller.  *)
let create_pcap_file_errors_out () =
  let check_create_file_error (module M : Errorful_writers.Errorful_writer) =
    let module E = Errorful_writers in
    let module Errorful_fs = E.Make(M) in
    let module Writer = Pcap_write.Make(Pcap.BE)(Errorful_fs) in
    (Writer.create_pcap_file (Errorful_fs.connect)
       "nowhere") >>= function
    | `Ok () -> OUnit.assert_failure "create_pcap_file falsely claimed success when it's
    impossible"
    | `Error e when e = M.error -> Lwt.return_unit
    | `Error _ -> OUnit.assert_failure "create_pcap_file returned an error type
    different from what the underlying FS returned"
  in
  check_create_file_error (module Errorful_writers.Not_a_directory) >>= fun () ->
  check_create_file_error (module Errorful_writers.Is_a_directory) >>= fun () ->
  check_create_file_error (module Errorful_writers.Directory_not_empty) >>= fun () ->
  check_create_file_error (module Errorful_writers.No_directory_entry) >>= fun () ->
  check_create_file_error (module Errorful_writers.File_already_exists) >>= fun () ->
  check_create_file_error (module Errorful_writers.No_space) >>= fun () ->
  check_create_file_error (module Errorful_writers.Format_not_recognised) >>= fun () ->
  check_create_file_error (module Errorful_writers.Unknown_error) >>= fun () ->
  check_create_file_error (module Errorful_writers.Block_device) >>= fun () ->
  Lwt.return_unit

let try_make_file now dirname filename =
  let module Writer = Pcap_write.Make(Pcap.BE)(FS_unix) in
  FS_unix.connect "test_fs" >>= or_fail >>= fun fs -> 
  FS_unix.mkdir fs dirname >>= or_fail >>= fun () ->
  Writer.create_pcap_file fs (dirname ^ "/" ^ filename) >>= or_fail >>= fun () ->
  Lwt.return fs

let create_pcap_file_makes_nonempty_file () =
  let module Writer = Pcap_write.Make(Pcap.BE)(FS_unix) in
  let now = Clock.time () in
  let dirname = ("create_pcap_file-" ^ (string_of_float now)) in
  let filename = "makes_nonempty_file.pcap" in
  try_make_file now dirname filename >>= fun fs ->
  FS_unix.size fs (dirname ^ "/" ^ filename) >>= or_fail >>= fun n ->
  OUnit.assert_equal false (0 = (Int64.compare n Int64.zero));
  Lwt.return_unit

let create_pcap_file_makes_readable_file () =
  let module Writer = Pcap_write.Make(Pcap.BE)(FS_unix) in
  let now = Clock.time () in
  let dirname = ("create_pcap_file-" ^ (string_of_float now)) in
  let filename = "makes_readable_file.pcap" in
  try_make_file now dirname filename >>= fun fs ->
  FS_unix.read fs (dirname ^ "/" ^ filename) 0 24 >>= or_fail >>= 
  fun _ -> Lwt.return_unit (* not checking contents, just readability *)

let create_pcap_file_makes_file_header () =
  let module Writer = Pcap_write.Make(Pcap.BE)(FS_unix) in
  let now = Clock.time () in
  let dirname = ("create_pcap_file-" ^ (string_of_float now)) in
  let filename = "makes_file_header.pcap" in
  try_make_file now dirname filename >>= fun fs ->
  FS_unix.size fs (dirname ^ "/" ^ filename) >>= or_fail >>= fun size ->
  OUnit.assert_equal ~msg:"readback file size" ~printer:string_of_int (Pcap.sizeof_pcap_header) (Int64.to_int size);
  FS_unix.read fs (dirname ^ "/" ^ filename) 0 (Int64.to_int size) 
  >>= or_fail >>= function
  | (contents::[]) -> (
      match Pcap.detect contents with
      | None -> OUnit.assert_failure "Couldn't autodetect endianness or make a
      reader based on the written file header"
      | Some header -> 
        let module Reader = (val header) in
        OUnit.assert_equal ~msg:"endianness test for readback file header" Pcap.Big Reader.endian;
        Lwt.return_unit )
  | [] -> OUnit.assert_failure "FS.read returned an empty list"
  | _ -> OUnit.assert_failure "Got *way* too much data; shouldn't need >1 page"

(* append_packet_to_file:
   we correctly write a zero-length packet (i.e., just header, no data)  
   if we request a write of >1 page size, it all gets written (superjumbo
   frames)
   written packets have the requested time
   written packets have the correct snaplen
   attempting to write to a file that hasn't been "initialized" fails
      (support for appends?)
   errors from the FS propagate upward, most importantly No_space
*)

let append_packet_errors_out () = 
  let module E = Errorful_writers in
  let expect_error dirname filename now packet 
      (module M : Errorful_writers.Errorful_writer) =
    let module Errorful_fs = E.Make(M) in
    let module Writer = Pcap_write.Make(Pcap.BE)(Errorful_fs) in
    Writer.append_packet_to_file (Errorful_fs.connect) 
      (dirname ^ "/" ^ "filename") (Pcap.sizeof_pcap_header) now packet >>= function 
    | `Ok _ -> OUnit.assert_failure "append_packet claimed success on an errorful FS"
    | `Error e when e = M.error -> Lwt.return_unit
    | `Error _ -> OUnit.assert_failure "append_packet returned an error that
    isn't the error its FS gave it"
  in
  let now = Clock.time () in
  let dirname = ("append_packet-" ^ (string_of_float now)) in
  let filename = "errors_out" in
  let packet = Cstruct.of_string "photograph of a cat.png" in
  let expect_error = expect_error dirname filename now packet in
  expect_error (module E.Not_a_directory) >>= fun () -> 
  expect_error (module E.Is_a_directory) >>= fun () ->
  expect_error (module E.Directory_not_empty) >>= fun () ->
  expect_error (module E.No_directory_entry) >>= fun () ->
  expect_error (module E.File_already_exists) >>= fun () ->
  expect_error (module E.No_space) >>= fun () ->
  expect_error (module E.Format_not_recognised) >>= fun () ->
  expect_error (module E.Unknown_error) >>= fun () ->
  expect_error (module E.Block_device) >>= fun () ->
  Lwt.return_unit

let append_packet_allows_zero_length () = 
  let module Writer = Pcap_write.Make(Pcap.BE)(FS_unix) in
  let now = Clock.time () in
  let dirname = ("append_packet-" ^ (string_of_float now)) in
  let filename = "allows_zero_length" in
  let packet = Cstruct.create 0 in
  try_make_file now dirname filename >>= fun fs ->
  Writer.append_packet_to_file fs 
    (dirname ^ "/" ^ filename) (Pcap.sizeof_pcap_header) now packet >>= function
  | `Error _ -> OUnit.assert_failure "Couldn't write a zero-length packet"
  | `Ok n -> 
    OUnit.assert_equal ~printer:string_of_int Pcap.sizeof_pcap_packet n;
    Lwt.return_unit

let append_packet_preserves_data () = 
  let module Writer = Pcap_write.Make(Pcap.BE)(FS_unix) in
  let now = Clock.time () in
  let dirname = ("append_packet-" ^ (string_of_float now)) in
  let filename = "preserves_data" in
  let packet = Cstruct.of_string "super important data do not lose" in
  try_make_file now dirname filename >>= fun fs ->
  Writer.append_packet_to_file fs 
    (dirname ^ "/" ^ filename) (Pcap.sizeof_pcap_header) now packet >>= or_fail
  >>= fun n ->
  FS_unix.read fs (dirname ^ "/" ^ filename) 0 4096 >>= or_fail >>= function
  | [] -> OUnit.assert_failure "file read returned empty list"
  | (buf::_::_) -> OUnit.assert_failure "file read returned way too much data"
  | (buf::[]) -> 
    match Pcap.detect buf with
    | None -> OUnit.assert_failure "written file was unreadable by the PCAP parser"
    | Some r -> let module Reader = (val r) in
      let iterator = Pcap.packets r (Cstruct.shift buf Pcap.sizeof_pcap_header) in
      let packets = 
        Cstruct.fold (fun l (header, body) -> 
            body :: l
          ) iterator [] in
      OUnit.assert_equal ~printer:string_of_int 1 (List.length packets);
      OUnit.assert_equal 
        ~printer:(fun a -> a) (Cstruct.to_string packet) (Cstruct.to_string
                                                            (List.hd packets));
      Lwt.return_unit

let append_packet_handles_big_packets () =
  let module Writer = Pcap_write.Make(Pcap.BE)(FS_unix) in
  let now = Clock.time () in
  let dirname = ("append_packet-" ^ (string_of_float now)) in
  let filename = "big_packets" in
  let packet = zero_cstruct (Cstruct.create 65536) in
  try_make_file now dirname filename >>= fun fs ->
  Writer.append_packet_to_file fs (dirname ^ "/" ^ filename)
    (Pcap.sizeof_pcap_header) now packet >>= or_fail >>= fun _ ->
  FS_unix.read fs (dirname ^ "/" ^ filename) 0 65560 >>= or_fail >>= function
  | [] -> OUnit.assert_failure "large packet read got an empty buffer"
  | bufs ->
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
    in
    let buf = combine_cstructs bufs in
    match Pcap.detect buf with
    | None -> OUnit.assert_failure "large packet read gave an unparseable file"
    | Some r -> let module Reader = (val r) in
      let iterator = Pcap.packets r (Cstruct.shift buf Pcap.sizeof_pcap_header) in
      let (headers, bodies) = Cstruct.fold (fun (hs, bs) (header, body) ->
          header::hs, body::bs
        ) iterator ([], []) in
      let printer = string_of_int in
      OUnit.assert_equal ~printer 1 (List.length headers);
      OUnit.assert_equal ~printer 1 (List.length bodies);
      OUnit.assert_equal ~printer:Int32.to_string 65535l 
        (Reader.get_pcap_packet_incl_len (List.hd headers));
      OUnit.assert_equal ~printer:Int32.to_string 65536l 
        (Reader.get_pcap_packet_orig_len (List.hd headers));
      OUnit.assert_equal ~printer 65535 (Cstruct.len (List.hd bodies));
      Lwt.return_unit

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
    "create_pcap_file_errors_out", `Quick, lwt_run create_pcap_file_errors_out;
    "create_pcap_file_makes_nonempty_file", `Quick, lwt_run create_pcap_file_makes_nonempty_file;
    "create_pcap_file_makes_readable_file", `Quick, lwt_run create_pcap_file_makes_readable_file;
    "create_pcap_file_makes_file_header", `Quick, lwt_run create_pcap_file_makes_file_header;
  ] in
  let append_packet_to_file = [
    "append_packet_errors_out", `Quick, lwt_run append_packet_errors_out;
    "append_packet_allows_zero_length", `Quick, lwt_run append_packet_allows_zero_length;
    "append_packet_preserves_data", `Quick, lwt_run append_packet_preserves_data;
    "append_packet_handles_big_packets", `Quick, lwt_run append_packet_handles_big_packets; 
  ] in
  Alcotest.run "Pcap_writer" [
    "create_file_header", create_file_header;
    "create_packet_header", create_packet_header;
    "create_pcap_file", create_pcap_file;
    "append_packet_to_file", append_packet_to_file;
  ]
