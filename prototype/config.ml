open Mirage

let main =
  foreign "Unikernel.Main" (console @-> kv_ro @->  job)

let disk1 = crunch "pcaps"
let tap = tap0

let tracing = mprof_trace ~size:100000 ()

let () =
  add_to_opam_packages["pcap-format"; "tcpip"];
  add_to_ocamlfind_libraries["pcap-format"; "tcpip.ethif"; "tcpip.ipv4";
                             "tcpip.udp"; "tcpip.dhcpv4"];
  register "parrot" ~tracing [ main $ default_console $ disk1 ]
