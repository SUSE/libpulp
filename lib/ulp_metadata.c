#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <link.h>

#include "ulp_metadata.h"
#include "ulp_common.h"
#include "error.h"


extern char __ulp_metadata_buffer[];

static struct ulp_metadata *__ulp_metadata_ref = NULL;

/* Functions from other modules, check what to do with them.  */
void *load_so_symbol(char *fname, void *handle);
void *load_so(char *obj);
struct ulp_applied_patch *ulp_get_applied_patch(const unsigned char *id);
extern struct ulp_patching_state __ulp_state;
/* Done functions of other modules.  */


int check_patch_sanity(struct ulp_metadata *);

int check_build_id(struct ulp_metadata *ulp);

int check_patch_dependencies(struct ulp_metadata *ulp);

int
compare_build_ids(struct dl_phdr_info *info,
                  size_t __attribute__((unused)) size, void *data);

/** @brief undload the loaded metadata object.
 *
 * Free its resources and set the global metadata object to NULL.
 */
int
unload_metadata(struct ulp_metadata *ulp)
{
  free_metadata(ulp);
  FREE_AND_NULLIFY(ulp);
  __ulp_metadata_ref = NULL;
  return 0;
}

/** @brief Load the .so file handle from the ulp metadata object.
 *
 * Livepatches code are stored in shared object (.so) files.  This function
 * will open the .so file and store its handler in the ulp object as well.
 *
 * @param ulp     The ulp metadata object.
 *
 * @return 0 if error, 1 if success.
 */
int
load_so_handlers(struct ulp_metadata *ulp)
{
  ulp->so_handler = load_so(ulp->so_filename);

  if (!ulp->so_handler) {
    WARN("Unable to load patch dl handler.");
    return 0;
  }

  return 1;
}

struct ulp_metadata *
load_metadata(int *err)
{
  struct ulp_metadata *ulp;
  if (__ulp_metadata_ref) {
    *err = 0;
    return __ulp_metadata_ref;
  }

  ulp = calloc(1, sizeof(struct ulp_metadata));
  if (!ulp) {
    WARN("Unable to allocate memory for ulp metadata");
    *err = errno;
    return NULL;
  }

  __ulp_metadata_ref = ulp;
  *err = parse_metadata(ulp);
  if (*err) {
    unload_metadata(ulp);
    WARN("Error in metadata load: %s.", libpulp_strerror(*err));
    return NULL;
  };

  *err = 0;
  return ulp;
}

/** @brief Parse metadata file in __ulp_metadata_buffer.
 *
 * When trigger command is issued, the metadata is written in
 * __ulp_metadata_buffer. Parse this metadata.
 *
 * @param ulp  The metadata output object
 * @return 0   0 if success, anything else if failure.
 */
int
parse_metadata(struct ulp_metadata *ulp)
{
  /* Initialize pointer and counter to keep track of metadata buffer parsing.
   */
  void *src = __ulp_metadata_buffer;
  size_t meta_size = ULP_METADATA_BUF_LEN;
  int ret;

  ret = parse_metadata_from_mem(ulp, src, meta_size);

  if (ret != ENONE || ulp->type == 2)
    goto metadata_clean;

  ret = check_patch_sanity(ulp);
  if (ret)
    goto metadata_clean;

  if (!load_so_handlers(ulp)) {
    ret = EDLOPEN;
    goto metadata_clean;
  }

metadata_clean:
  memset(src, 0, ULP_METADATA_BUF_LEN);
  return ret;
}

/** @brief Check if the patch metadata object is sane.
 *
 * This function checks if the given metadata object in `ulp` is sane in order
 * to procceed with the patching.
 *
 * @param ulp        The metadata object.
 * @return           0 if success, anything else if error.
 */
int
check_patch_sanity(struct ulp_metadata *ulp)
{
  int ret;
  if (!check_build_id(ulp))
    return EBUILDID;
  ret = check_patch_dependencies(ulp);
  if (ret)
    return ret;
  if (ulp_get_applied_patch(ulp->patch_id)) {
    return EAPPLIED;
  }

  return 0;
}

/** @brief Check if the build id in the patch matches some .
 *
 * Check if the build id in the patch was already compared and it is safe to
 * continue with livepatching.
 *
 * @param ulp         The parsed ulp_metadata object.
 * @return            1 if success, 0 if error.
 */
int
check_build_id(struct ulp_metadata *ulp)
{
  dl_iterate_phdr(compare_build_ids, ulp);
  if (!ulp->objs->build_id_check) {
    WARN("Could not match patch target build id %s.", ulp->objs->name);
    return 0;
  }

  return 1;
}

/** @brief Check the dependencies of the livepatch given in metadata.
 *
 * This function will check if the patch given in the parsed ulp_metadata
 * object have its dependencies fullfiled.
 *
 * @param ulp         The parsed ulp_metadata object.
 *
 * @return            0 if success, EDEPEND if dependencies are not met.
 */
int
check_patch_dependencies(struct ulp_metadata *ulp)
{
  struct ulp_applied_patch *patch;
  struct ulp_dependency *dep;

  for (dep = ulp->deps; dep != NULL; dep = dep->next) {
    for (patch = __ulp_state.patches; patch != NULL; patch = patch->next) {
      if (memcmp(patch->patch_id, dep->dep_id, 32) == 0) {
        dep->patch_id_check = 1;
        break;
      }
    }
  }

  for (dep = ulp->deps; dep != NULL; dep = dep->next) {
    if (dep->patch_id_check == 0) {
      WARN("Patch does not match dependencies.");
      return EDEPEND;
    }
  }
  return 0;
}

/** build_id_note structure, holding information about the build id.  */
struct build_id_note
{
  /* The NHdr ELF.  See elf.h for more information.   */

  /** Size of the name structure.  */
  uint32_t namesz;
  /** Length of the build id.  */
  uint32_t descsz;
  /** Unknown.  */
  uint32_t type;
  /** Name.  */
  char name[4]; /* Note name for build-id is "GNU\0" */
  /** Build id.  */
  unsigned char build_id[0];
};

/** @brief Function used by dl_iterate_phdr to check if there are some library
 *        that matches the buildid in the `data` ulp_metadata object.
 */
int
compare_build_ids(struct dl_phdr_info *info,
                  size_t __attribute__((unused)) size, void *data)
{

/** Align `val` to `align` bytes.  */
#define ALIGN(val, align) (((val) + (align) - 1) & ~((align) - 1))

  struct ulp_metadata *ulp = (struct ulp_metadata *)data;

  for (unsigned i = 0; i < info->dlpi_phnum; ++i) {
    if (info->dlpi_phdr[i].p_type != PT_NOTE)
      continue;

    struct build_id_note *note =
        (struct build_id_note *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
    ptrdiff_t size = info->dlpi_phdr[i].p_filesz;

    while (size >= (ptrdiff_t)sizeof(struct build_id_note)) {
      if (note->type == NT_GNU_BUILD_ID && note->namesz == 4 &&
          note->descsz >= 16) {

        /* Check if build matches.  */
        if (note->descsz == ulp->objs->build_id_len &&
            memcmp(ulp->objs->build_id, note->build_id, note->descsz)) {
          ulp->objs->build_id_check = 1;
          return 1;
        }

        /* Does not match.  Go to another lib.  */
        break;
      }
      size_t offset = (sizeof(uint32_t) * 3 + ALIGN(note->namesz, 4) +
                       ALIGN(note->descsz, 4));
      note = (struct build_id_note *)((char *)note + offset);
      size -= offset;
    }
  }

  return 0;

#undef ALIGN
}
