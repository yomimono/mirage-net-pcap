module type Pcap_writer = sig

  type error
  type fs

  val create_file_header : Cstruct.t -> unit
  val create_packet_header : Cstruct.t -> float -> int -> unit
  val create_pcap_file : fs -> string -> [ `Ok of unit | `Error of error ] Lwt.t
  val append_packet_to_file : fs -> string -> int -> float -> Cstruct.t -> 
    [ `Ok of int | `Error of error ] Lwt.t

end

module Make (Pcap_impl : Pcap.HDR) (FS : V1_LWT.FS with type page_aligned_buffer
                                     = Cstruct.t) = struct

  type fs = FS.t
  type error = FS.error

  (* write a pcap file header into buf; don't catch Cstruct exceptions if the
     buffer is too small *)
  let create_file_header header =
    Pcap_impl.set_pcap_header_magic_number header Pcap.magic_number;
    Pcap_impl.set_pcap_header_version_major header Pcap.major_version;
    Pcap_impl.set_pcap_header_version_minor header Pcap.minor_version;
    Pcap_impl.set_pcap_header_thiszone header 0l; (* assume all clocks are GMT, since
                                                     even functorizing over something
                                                     of type CLOCK doesn't get us tz
                                                     info *)
    Pcap_impl.set_pcap_header_sigfigs header 0l; (* according to wireshark wiki, this
                                                    is how everyone rolls *)
    Pcap_impl.set_pcap_header_snaplen header 65535l; (* TODO: this is pretty magic *)
    Pcap_impl.set_pcap_header_network header (Pcap.Network.to_int32
                                                Pcap.Network.Ethernet)

  (* TODO: overwrite capability would be nice *)
  let create_pcap_file fs file =
    let (>>=) = Lwt.bind in
    FS.create fs file >>= function
    | `Error q -> Lwt.return (`Error q)
    | `Ok () ->
      (* write a pcap header to that file *)
      (* ocaml-pcap doesn't seem to have a nice default for this, although
         it does expose the type *)
      let header = Cstruct.create Pcap.sizeof_pcap_header in
      create_file_header header;
      FS.write fs file 0 header

  let create_packet_header header time packet_size =
    Pcap_impl.set_pcap_packet_ts_sec header (Int32.of_float time);
    Pcap_impl.set_pcap_packet_ts_usec header 
      (Int32.of_float ((fst (modf time)) *.  1000000.));
    Pcap_impl.set_pcap_packet_incl_len header (Int32.of_int (min packet_size 65535));
    Pcap_impl.set_pcap_packet_orig_len header (Int32.of_int packet_size)

  let append_packet_to_file fs file offset time packet =
    let (>>=) = Lwt.bind in
    let header_size = Pcap.sizeof_pcap_packet in
    let packet_size = Cstruct.len packet in
    let copy_size = min 65535 packet_size in
    let header = Cstruct.create (header_size + copy_size) in
    create_packet_header header time packet_size;
    Cstruct.blit packet 0 header header_size copy_size;
    FS.write fs file offset header >>= function
    | `Ok () -> Lwt.return (`Ok (header_size + copy_size))
    | `Error q -> Lwt.return (`Error q)

end
