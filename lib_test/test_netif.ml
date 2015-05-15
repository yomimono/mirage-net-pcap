open Lwt

module Time = struct
  type 'a io = 'a Lwt.t
  let sleep = Lwt_unix.sleep
end

let test_dir = "_tests/test_directory"
let dhcp_file = "dhcp.pcap" (* 4-packet dhcp transaction *)
let arp_dhcp_file = "arp_dhcp.pcap" (* 4-packet dhcp transaction + arp *)
let mac = Macaddr.of_string_exn "00:16:3e:aa:a2:15"

let timestamp str = (str ^ "-" ^ (string_of_float (Clock.time ())))

let fs_or_error = function
  | `Error e -> OUnit.assert_failure (FS_unix.string_of_error e)
  | `Ok q -> Lwt.return q

let netif_or_error ~printer = function
  | `Error e -> OUnit.assert_failure (printer e)
  | `Ok n -> Lwt.return n

let fail_on_success str = function
  | `Ok _ -> OUnit.assert_failure str
  | `Error _ -> Lwt.return_unit


let connect_would_overwrite () =
  let module N = Netif.Make(FS_unix)(Time)(Clock) in
  let directory = timestamp "connect_would_overwrite" in
  let file = "file!!!" in
  FS_unix.connect test_dir >>= fs_or_error >>= fun fs ->
  FS_unix.write fs (directory ^ "/" ^ file) 0 
    (Cstruct.of_string "super important packet trace do not delete")
     >>= fs_or_error >>= fun () ->
  let id = N.id_of_desc ~timing:None ~mac ~source:fs ~read:dhcp_file
      ~write:(directory ^ "/" ^ file) in
  N.connect id >>= fail_on_success "netif.connect overwrote an extant file"

let connect_read_non_extant () =
  let module N = Netif.Make(FS_unix)(Time)(Clock) in
  let directory = timestamp "connect_read_non_extant" in
  let file = directory ^ "/cats/not there! :)" in
  FS_unix.connect test_dir >>= fs_or_error >>= fun fs ->
  let id = N.id_of_desc ~timing:None ~mac ~source:fs ~read:file ~write:file in
  N.connect id >>= 
  fail_on_success "netif.connect claimed success for an absent read file"

let connect_read_not_pcap () =
  let module N = Netif.Make(FS_unix)(Time)(Clock) in
  let directory = timestamp "connect_read_not_pcap" in
  let file = "not_a_pcap.pcap" in
  FS_unix.connect test_dir >>= fs_or_error >>= fun fs ->
  FS_unix.write fs (directory ^ "/" ^ file) 0 
    (Cstruct.of_string "super important packet trace do not delete") >>=
  fs_or_error >>= fun () ->
  let id = N.id_of_desc ~timing:None ~mac ~source:fs ~read:dhcp_file
      ~write:(directory ^ "/" ^ file) in
  N.connect id >>= fail_on_success "netif.connect claimed success reading a file
    that bears no resemblance to a valid pcap"

let mac_as_requested () =
  let module N = Netif.Make(FS_unix)(Time)(Clock) in
  let directory = timestamp "connect_read_not_pcap" in
  let write = (directory ^ "/nothing.pcap") in
  FS_unix.connect test_dir >>= fs_or_error >>= fun fs ->
  let id = N.id_of_desc ~timing:None ~mac ~source:fs ~read:dhcp_file ~write in
  N.connect id >>= netif_or_error ~printer:N.string_of_error >>= fun netif ->
  OUnit.assert_equal ~printer:Macaddr.to_string mac (N.mac netif);
  Lwt.return_unit

let lwt_run f () = Lwt_main.run (f ())

let () =
  let connect = [ 
    "connect_would_overwrite", `Quick, lwt_run connect_would_overwrite;
    "connect_read_non_extant", `Quick, lwt_run connect_read_non_extant;
    "connect_read_not_pcap", `Quick, lwt_run connect_read_not_pcap;
  ] in
  let write = [ ] in
  let listen = [ ] in
  let mac = [ 
    "mac_as_requested", `Quick, lwt_run mac_as_requested;
  ] in
  let get_stats_counters = [ ] in
  let reset_stats_counters = [ ] in
  let disconnect = [ ] in
  Alcotest.run "Netif" [
    "connect", connect;
    "disconnect", disconnect;
    "write", write;
    "listen", listen;
    "mac", mac;
    "get_stats_counters", get_stats_counters;
    "reset_stats_counters", reset_stats_counters;
  ]
