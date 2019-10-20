#!/usr/bin/lua

function usage()
  print("usage:")
  print(" ulp_dispatcher check <metadata>        # to list unpatched processes")
  print(" ulp_dispatcher patch <metadata>        # to patch all processes")
  print(" ulp_dispatcher patch <metadata> <pid>  # to patch a single process")
end

function read_uint32(file)
  local b1 = string.byte(file:read(1))
  local b2 = string.byte(file:read(1))
  local b3 = string.byte(file:read(1))
  local b4 = string.byte(file:read(1))

  if not b1 or not b2 or not b3 or not b4 then
    print("Unable to read uint32")
    return nil
  end

  local n = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
  n = (n > 2147483647) and (n - 4294967296) or n

  return n
end

function read_uint8(file)
  local b1 = string.byte(file:read(1))
  return b1
end

function resolve_link(object)

  local link = io.popen("file " .. object)
  local line = link:read("*line")

  if not line then
    print("DISPATCHER ERROR: Unable to check link: " .. object)
    return nil
  end

  path, target = string.match(line, "(.*)/.*: symbolic link to (.*)")
  if path then
    object = path .. "/" .. target
  end

  return object
end

function parse_metadata(metadata_file)
  local metadata = {}

  local file = io.open(metadata_file, "rb")
  if not file then
    print("DISPATCHER ERROR: Unable to open: " .. metadata_file)
    return nil
  end

  metadata["type"] = read_uint8(file)
  metadata["patch_id"] = file:read(32)
  metadata["patch_object_name_len"] = read_uint32(file)
  metadata["patch_object"] = file:read(metadata["patch_object_name_len"])
  metadata["build_id_len"] = read_uint32(file)
  metadata["build_id"] = file:read(metadata["build_id_len"])
  metadata["target_object_name_len"] = read_uint32(file)
  metadata["target_object"] = file:read(metadata["target_object_name_len"])

  -- check if target object is symbolic link and resolve it
  metadata["target_object"] = resolve_link(metadata["target_object"])

  file:close()
  return metadata
end

function get_target_list(metadata)
  local targets = {}
  local procs = {}

  local ls = io.popen("ls /proc")
  while true do
    local line = ls:read("*line")
    if not line then
      break
    end

    proc = string.match(line, "^(%d+)$")
    if proc then
      procs[#procs+1] = proc
    end

  end
  ls:close()

  local i = 1
  while i < #procs do
    local cmd = "pmap " .. procs[i] .. " | grep -q " .. metadata["target_object"]
    if os.execute(cmd) then
      targets[#targets+1] = procs[i]
    end
    i = i + 1
  end

  return targets
end

function check_all(metadata_file)
  local ulp_check = "/usr/bin/ulp_check "
  local metadata = parse_metadata(metadata_file)
  if not metadata then return nil end

  local targets = get_target_list(metadata)
  local i = 1
  while i < #targets+1 do
    local check = os.execute(ulp_check .. targets[i] .. " " .. metadata_file)
    if check == 1 then
      print(targets[i] .. " was not patched\n")
    end
    i = i + 1
  end
end

function check_single(metadata, metadata_file, pid)
  local ulp_check = "/usr/bin/ulp_check "
  local check = os.execute(ulp_check .. pid .. " " .. metadata_file)
  if check == 1 then return 0 end
  return 1
end

function patch_all(metadata_file)
  local ulp_patch = "/usr/bin/ulp_trigger "
  local metadata = parse_metadata(metadata_file)
  if not metadata then return nil end

  local targets = get_target_list(metadata)
  local i = 1
  while i < #targets+1 do
    if check_single(metadata, metadata_file, targets[i]) then
      local check = os.execute(ulp_patch .. targets[i] .. " " .. metadata_file)
      if not check then
        print("Unable to patch process " .. targets[i] .. " - please try again:")
        print(" ulp_dispatcher patch " .. metadata_file .. " " .. targets[i])
      end
    else
      print(targets[i] .. " is already patched. Not patching again\n")
    end
    i = i + 1
  end
end

function patch_single(metadata, pid)
  local ulp_patch = "/usr/bin/ulp_patch "
  local metadata = parse_meatadata(metadata_file)

  local check = os.execute(ulp_patch .. pid .. " " .. metadata_file)
  if check then
    print("Unable to patch process " .. targets[i] .. " - please try again:")
    print("ulp_dispatcher patch " .. metadata_file .. " " .. targets[i])
  end
end

if ( #arg < 2 or #arg > 3 ) then
  usage()
  os.exit()
end

if (arg[1] == "check") then
  check_all(arg[2])
  os.exit()
end

if (arg[1] == "patch") then
  if (#arg == 2) then
    patch_all(arg[2])
  else
    patch_single(arg[2], arg[3])
  end
  os.exit()
end

usage()
os.exit()
