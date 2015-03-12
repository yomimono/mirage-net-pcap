module Make (K: V1_LWT.KV_RO) (T: V1_LWT.TIME) : sig
  include V1.NETWORK
    with type 'a io = 'a Lwt.t
     and type page_aligned_buffer = Io_page.t
     and type buffer = Cstruct.t
     and type macaddr = Macaddr.t

  val connect : id -> [ `Error of error | `Ok of t ] io

  val id_of_desc : ?timing:float option -> mac:Macaddr.t -> source:K.t -> read:string -> id
  (** Generate an id for use with [connect] with MAC address [mac].
      [source] is a KV_RO.t from which to attempt to read a file named [read].
      use [timing] to accelerate or decelerate playback of packets.  1.0 is
      playback at the original recorded rate.  numbers greater than 1.0 will
      delay; numbers smaller than 1.0 will speed up playback.  None gives no
      artificial delay and plays back packets as quickly as possible. *)

  val get_written : t -> Cstruct.t list
  (** return all frames written to this netif, in the order they were written.
     Each element in the list represents the contents of a call to `write`. *)
end
