open Mirage

let main =
  foreign "Unikernel.Main" (console @-> kv_ro @-> network @-> job)

let disk1 = crunch "pcaps"
let tap = tap0

let tracing = mprof_trace ~size:100000 ()

let () =
  add_to_opam_packages["pcap-format"];
  add_to_ocamlfind_libraries["pcap-format"];
  register "parrot" ~tracing [ main $ default_console $ disk1 $ tap0 ]
