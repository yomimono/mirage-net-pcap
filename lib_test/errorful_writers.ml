module Generic : sig
  type block_device_error = string
  type error = [
    | `Not_a_directory of string             (** Cannot create a directory entry in a file *)
    | `Is_a_directory of string              (** Cannot read or write the contents of a directory *)
    | `Directory_not_empty of string         (** Cannot remove a non-empty directory *)
    | `No_directory_entry of string * string (** Cannot find a directory entry *)
    | `File_already_exists of string         (** Cannot create a file with a duplicate name *)
    | `No_space                              (** No space left on the block device *)
    | `Format_not_recognised of string       (** The block device appears to not be formatted *)
    | `Unknown_error of string
    | `Block_device of block_device_error
  ]
end = struct
  type block_device_error = string
  type error = [
    | `Not_a_directory of string             (** Cannot create a directory entry in a file *)
    | `Is_a_directory of string              (** Cannot read or write the contents of a directory *)
    | `Directory_not_empty of string         (** Cannot remove a non-empty directory *)
    | `No_directory_entry of string * string (** Cannot find a directory entry *)
    | `File_already_exists of string         (** Cannot create a file with a duplicate name *)
    | `No_space                              (** No space left on the block device *)
    | `Format_not_recognised of string       (** The block device appears to not be formatted *)
    | `Unknown_error of string
    | `Block_device of block_device_error
  ]
end

module Not_a_directory : sig
  include V1.FS with type 'a io = 'a Lwt.t and type page_aligned_buffer =
                                                   Cstruct.t
  val connect : t
end = struct
  type 'a io = 'a Lwt.t
  type t = {unit: unit} (* stateless, since we always return an error *)
  type page_aligned_buffer = Cstruct.t
  type block_device_error = Generic.block_device_error
  type error = Generic.error
  type id = string
  type stat = {
    filename: string; (** Filename within the enclosing directory *)
    read_only: bool;  (** True means the contents are read-only *)
    directory: bool;  (** True means the entity is a directory; false means a file *)
    size: int64;      (** Size of the entity in bytes *)
  }

  let format _ _ = Lwt.return (`Error (`Not_a_directory "Not a directory"))
  let create = format
  let mkdir = format
  let destroy = format
  let stat = format
  let listdir = format
  let size = format
  let write a b _ _ = format a b
  let read = write
  let disconnect _ = Lwt.return_unit

  let connect = { unit = ()}

end
