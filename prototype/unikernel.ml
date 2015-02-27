open V1_LWT
open Lwt

module Main (C: CONSOLE) (K: KV_RO) (N: NETWORK) = struct
  let parrot c netif packet = (*
    N.writev netif [packet] >>= fun () -> *)
    C.log c "packet:\n";
    Cstruct.hexdump packet
  
  let start c k n =
    let chunk_size = 4096 in
    let file = "packet_of_death.pcap" in
    K.read k file 0 chunk_size >>= fun result -> 
    match result with
    | `Error _ -> 
      C.log c (Printf.sprintf "I know of no file called %s \n" file);
      Lwt.return_unit
    | `Ok bufs -> (List.iter (parrot c n) bufs; Lwt.return_unit)

end
