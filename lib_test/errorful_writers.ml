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
  type 'a io = 'a Lwt.t
  type t = {unit: unit} (* stateless, since we always return an error *)
  type page_aligned_buffer = Cstruct.t
  type id = string
  type stat = {
    filename: string; (** Filename within the enclosing directory *)
    read_only: bool;  (** True means the contents are read-only *)
    directory: bool;  (** True means the entity is a directory; false means a file *)
    size: int64;      (** Size of the entity in bytes *)
  }
  val connect : t
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
  type 'a io = 'a Lwt.t
  type t = {unit: unit} (* stateless, since we always return an error *)
  type page_aligned_buffer = Cstruct.t
  type id = string
  type stat = {
    filename: string; (** Filename within the enclosing directory *)
    read_only: bool;  (** True means the contents are read-only *)
    directory: bool;  (** True means the entity is a directory; false means a file *)
    size: int64;      (** Size of the entity in bytes *)
  }

  let connect = { unit = ()}
end

module type Errorful_writer = sig
  val error : Generic.error
end

module Make (E: Errorful_writer) : sig
  include V1.FS with type 'a io = 'a Lwt.t 
                 and type page_aligned_buffer = Cstruct.t
                 and type block_device_error = string
  val connect : t
  val disconnect : t -> unit Lwt.t
end = struct
  let disconnect _ = Lwt.return_unit
  let format _ _ = Lwt.return (`Error E.error)
  include Generic
  let create, mkdir, destroy, stat, listdir, size = format, format, format,
                                                    format, format, format
  let write a b _ _ = format a b
  let read = write
end

(* implementations of V1.FS that always return errors corresponding to their names.  *)
module Not_a_directory = struct let error = `Not_a_directory "Not_a_directory" end
module Is_a_directory = struct let error = `Is_a_directory "Is_a_directory" end
module Directory_not_empty = struct let error = `Directory_not_empty "Directory_not_empty" end
module No_space = struct let error = `No_space end
module Format_not_recognised = struct let error = `Format_not_recognised
                                          "Format_not_recognised" end
module Unknown_error = struct let error = `Unknown_error "Unknown_error" end
module File_already_exists = struct let error = `File_already_exists "File_already_exists" end
module Block_device = struct let error = `Block_device "Block_device" end
module No_directory_entry = struct 
  let error = `No_directory_entry ("No_directory_entry", "No_directory_entry")
end

