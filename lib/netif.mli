open Mirage

module Netif (K: V1_LWT.KV_RO) (T: V1_LWT.TIME) : sig
  include V1.NETWORK
    with type 'a io = 'a Lwt.t
     and type page_aligned_buffer = Cstruct.t
     and type buffer = Cstruct.t
     and type macaddr = Macaddr.t

  val id_of_desc : source:K.t -> read:string -> id
end
