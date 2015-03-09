open V1_LWT
open Lwt

module Main (C: CONSOLE) (K: KV_RO) = struct

  let start c k =
    let module P = Reading_netif(K) in
    let module E = Ethif.Make(P) in
    let module I = Ipv4.Make(E) in
    let module U = Udp.Make(I) in
    let module D = Dhcp_clientv4.Make(C)(OS.Time)(Random)(U) in

    let or_error c name fn t =
      fn t >>= function 
      | `Error e -> fail (Failure ("Error starting " ^ name))
      | `Ok t -> return t
    in
    let red fmt    = Printf.sprintf ("\027[31m"^^fmt^^"\027[m") in
    let green fmt  = Printf.sprintf ("\027[32m"^^fmt^^"\027[m") in
    let yellow fmt = Printf.sprintf ("\027[33m"^^fmt^^"\027[m") in
    let blue fmt   = Printf.sprintf ("\027[36m"^^fmt^^"\027[m") in
        
    let file = "mirage_dhcp_discover.pcap" in
    let pcap_netif_id = P.id_of_desc ~source:k ~read:file in
    (* build interface on top of netif *)
    or_error c "pcap_netif" P.connect pcap_netif_id >>= fun p ->
    or_error c "ethif" E.connect p >>= fun e ->
    or_error c "ipv4" I.connect e >>= fun i ->
    or_error c "udpv4" U.connect i >>= fun u -> 
    let dhcp, offers = D.create c (P.mac p) u in 
    C.log_s c "beginning listen..." >>= fun () ->
    P.listen p (
      E.input 
        ~arpv4:(fun buf -> 
            return (C.log c (red "arp packet")))
        ~ipv4:(
        I.input 
          ~tcp:(fun ~src ~dst buf -> return (C.log c (blue "tcp packet from %s"
                                                (Ipaddr.V4.to_string src))))
          ~udp:(
            U.input ~listeners:
              (fun ~dst_port -> Some (fun ~src ~dst ~src_port buf ->
                 return (C.log c (blue "udp packet on port %d" dst_port))))
              u
          ) 
          ~default:(
            fun ~proto ~src ~dst buf -> return (
              C.log c (green "other packet, proto %d, src %s, dst %s" proto
                         (Ipaddr.V4.to_string src) (Ipaddr.V4.to_string dst)))
          ) 
          i
      ) ~ipv6:(fun b -> C.log_s c (yellow "ipv6")) e
    )

end
