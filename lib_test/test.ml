open Lwt.Infix

let tests = [
"id:000000,sig:06,src:000000,op:flip1,pos:32";
"id:000000,sig:06,src:000000,op:flip4,pos:495";
"id:000001,sig:06,src:000000,op:flip1,pos:32";
"id:000001,sig:06,src:000000,op:flip1,pos:35";
"id:000001,sig:06,src:000000,op:flip4,pos:612";
"id:000002,sig:06,src:000000,op:ext_AO,pos:429";
"id:000002,sig:06,src:000000,op:flip1,pos:264";
"id:000002,sig:06,src:000000,op:flip1,pos:32";
"id:000003,sig:06,src:000000,op:flip1,pos:33";
"id:000003,sig:06,src:000000,op:havoc,rep:64";
"id:000004,sig:06,src:000000,op:flip1,pos:149";
"id:000004,sig:06,src:000005,op:havoc,rep:128";
"id:000005,sig:06,src:000000,op:flip1,pos:380";
"id:000005,sig:06,src:000007,op:arith32,pos:670,val:+2";
"id:000006,sig:06,src:000000,op:flip1,pos:671";
"id:000006,sig:06,src:000007,op:ext_AO,pos:610";
"id:000007,sig:06,src:000000,op:flip2,pos:612";
"id:000007,sig:06,src:000001,op:havoc,rep:4";
"id:000008,sig:06,src:000000,op:flip4,pos:498";
"id:000008,sig:06,src:000059,op:int32,pos:32,val:+4096";
"id:000009,sig:06,src:000000,op:arith8,pos:33,val:-9";
"id:000009,sig:06,src:000068,op:int32,pos:1075,val:+256";
"id:000010,sig:06,src:000000,op:arith8,pos:148,val:-9";
"id:000010,sig:06,src:000081,op:flip1,pos:1251";
"id:000011,sig:06,src:000000,op:arith8,pos:499,val:+20";
"id:000011,sig:06,src:000081,op:havoc,rep:128";
"id:000012,sig:06,src:000000,op:havoc,rep:4";
"id:000012,sig:06,src:000093,op:arith16,pos:1285,val:be:-26";
"id:000013,sig:06,src:000005,op:havoc,rep:64";
"id:000014,sig:06,src:000008,op:flip2,pos:266";
"id:000015,sig:06,src:000008,op:arith8,pos:90,val:+14";
"id:000016,sig:06,src:000008,op:ext_AO,pos:664";
"id:000017,sig:06,src:000049,op:havoc,rep:2";
]

module P = Netif.Make(Kvro_fs_unix)(OS.Time)
let sample_dir = "samples"

let or_error (str : string) f n =
  f n >>= function
  | `Error _ -> Alcotest.fail str
  | `Ok p -> Lwt.return p

let or_exit connect_fn connect_args continuation continuation_args =
  connect_fn connect_args >>= function
  | `Error _ -> Alcotest.fail "Couldn't connect" ;Lwt.return_unit
  | `Ok p -> continuation continuation_args p

let get_id file =
  or_error "couldn't open source directory -- does it exist?"
    Kvro_fs_unix.connect sample_dir >>= fun fs ->
  Lwt.return (P.id_of_desc ~timing:None ~mac:Macaddr.broadcast ~source:fs
                ~read:file)

let err_init id =
  or_error "failed to read the pcap file -- bad header?" P.connect id

let exit_init id fn args =
  or_exit P.connect id fn args

let read_all () p =
  P.listen p (fun _ -> Lwt.return_unit)

let test file () =
  get_id file >>= fun id ->
  exit_init id read_all ()

let afl_regressions = List.map (fun file ->
    file, `Quick, (fun () -> Lwt_main.run (test file ()))) tests

let () =
  Alcotest.run "mirage-net-pcap" [
    "afl_regressions", afl_regressions;
  ]
