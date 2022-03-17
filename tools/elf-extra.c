/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2019-2022 SUSE Software Solutions GmbH
 *
 *  This file is part of libpulp.
 *
 *  libpulp is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  libpulp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with libpulp.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "elf-extra.h"
#include "error_common.h"
#include "ulp_common.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Extra ELF functions.  */

void
unload_elf(Elf **elf, int *fd)
{
  if (*fd > 0)
    close(*fd);
  if (elf)
    elf_end(*elf);
  *fd = 0;
  *elf = NULL;
}

Elf *
load_elf(const char *obj, int *fd)
{
  Elf *elf;

  elf_version(EV_CURRENT);

  *fd = open(obj, O_RDONLY);
  if (*fd == -1) {
    WARN("error opening %s: %s", obj, strerror(errno));
    return NULL;
  }

  elf = elf_begin(*fd, ELF_C_READ, NULL);
  if (!elf) {
    WARN("error invoking elf_begin(): %s", elf_errmsg(-1));
    close(*fd);
    return NULL;
  }
  return elf;
}

Elf_Scn *
get_elfscn_by_name(Elf *elf, const char *name)
{
  size_t i, nsecs, shstrndx;
  Elf_Scn *s;
  GElf_Shdr sh;
  char *sec_name;

  if (elf_getshdrnum(elf, &nsecs)) {
    return NULL;
  }

  for (i = 0; i < nsecs; i++) {
    s = elf_getscn(elf, i);
    if (!s) {
      return NULL;
    }
    gelf_getshdr(s, &sh);

    elf_getshdrstrndx(elf, &shstrndx);
    sec_name = elf_strptr(elf, shstrndx, sh.sh_name);
    if (strcmp(sec_name, name) == 0)
      return s;
  }
  return NULL;
}

Elf_Scn *
get_elf_section(Elf *elf, ElfW(Word) sht_type)
{
  size_t i, nsecs;
  Elf_Scn *s;
  GElf_Shdr sh;

  if (elf_getshdrnum(elf, &nsecs)) {
    WARN("error invoking elf_getshdrnum()");
    return NULL;
  }

  for (i = 0; i < nsecs; i++) {
    s = elf_getscn(elf, i);
    if (!s) {
      WARN("error invoking elf_getscn()");
      return NULL;
    }
    gelf_getshdr(s, &sh);

    if (sh.sh_type == sht_type) {
      return s;
    }
  }
  return NULL;
}

/** @brief Embed livepatch metadata into .so container
 *
 * Older versions of libpulp required two files to operate, a livepatch
 * metadata (.ulp) and a livepatch container (.so). This function embeds
 * the metadata into the container, so only one file is necessary to operate.
 *
 * @param elfinput   Elf object to livepatch container. Should be NULL (i.e.
 * not open by libelf).
 * @param elf_path   Path to livepatch container (ELF .so file).
 * @param metadata   Livepatch metadata path (old .ulp).
 * @param section_name Name of the new section to be created.
 *
 * @return 0 on success. Anything else on failure.
 */
int
embed_patch_metadata_into_elf(Elf *elfinput, const char *elf_path,
                              const char *metadata, const char *section_name)
{
  int ret = 0;
  const char *objcopy_path = "/usr/bin/objcopy";

  /* Assert that libelf is not holding the ELF object.  We will use objcopy fo
     now.*/
  assert(elfinput == NULL);

  if (access(objcopy_path, F_OK) != 0) {
    WARN("objcopy not found in %s", objcopy_path);
    return ENOENT;
  }

  int fd;
  /* Load ELF with libelf to check if we already have an .ulp section.  */
  Elf *elf = load_elf(elf_path, &fd);
  bool ulp_section_exists = (get_elfscn_by_name(elf, section_name) != NULL);
  unload_elf(&elf, &fd);

  const char *argv[16];
  int argc = 0;

  char ulp_eq_filename[128];
  int n = snprintf(ulp_eq_filename, 128, "%s=%s", section_name, metadata);

  if (n >= 120) {
    WARN("Path to temporary metadata larger than 120 characters");
    return EOVERFLOW;
  }

  /* Prepare objcopy parameters.  */
  argv[argc++] = objcopy_path;
  argv[argc++] = ulp_section_exists ? "--update-section" : "--add-section";
  argv[argc++] = ulp_eq_filename;
  argv[argc++] = elf_path;
  argv[argc++] = elf_path;
  argv[argc] = NULL;

  /* Launch objcopy.  */
  pid_t pid = vfork();
  if (pid == 0) {
    execv(objcopy_path, (char *const *)argv);
  }
  else {
    int wi;
    waitpid(pid, &wi, 0);

    if (WIFEXITED(wi))
      ret = WEXITSTATUS(ret);
  }

  return ret;
}
