module Make (K: V1_LWT.KV_RO) (T: V1_LWT.TIME) : sig
  include V1.NETWORK
    with type 'a io = 'a Lwt.t
     and type page_aligned_buffer = Io_page.t
     and type buffer = Cstruct.t
     and type macaddr = Macaddr.t

  (* use "timing" to accelerate or decelerate playback of packets.  1.0 is
     playback at the original recorded rate.  numbers greater than 1.0 will
     delay; numbers smaller than 1.0 will speed up playback.  None gives no
     delay at all. *)
  val id_of_desc : ?timing:float option -> source:K.t -> read:string -> id
end
