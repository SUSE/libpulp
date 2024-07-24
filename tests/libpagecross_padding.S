/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2020-2021 SUSE Software Solutions GmbH
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

/*
 * From the start of a page (.align <PAGE_SIZE>), fill the memory with
 * garbage up to the end of the page less 16 bytes (.fill <FILL_SIZE>),
 * so that the prologue of the to-be-patched function (in libpage.c)
 * crosses a page boundary.
 */
.set FILL_SIZE, PAGE_SIZE-16
.section .text
.fill FILL_SIZE, 1, 0xCC
