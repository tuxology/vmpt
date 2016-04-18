/*
 * vmpt.c
 * 
 * VMCS based analysis using Intel Processor Trace
 * Suchakra Sharma <suchakrapani.sharma@polymtl.ca>
 *
 * Based on ptdump reference implementation, 
 * Copyright (c) 2013-2016, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "intel-pt.h"

#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

static int usage(const char *name)
{
    fprintf(stderr,
            "usage: %s <ptfile>\n",
            name);
    return -1;
}

static int no_file_error(const char *name)
{
    fprintf(stderr, "%s: No processor trace file specified.\n", name);
    return -1;
}

static int unknown_option_error(const char *arg, const char *name)
{
    fprintf(stderr, "%s: unknown option: %s.\n", name, arg);
    return -1;
}

static int parse_range(char *arg, uint64_t *begin, uint64_t *end)
{
    char *rest;

    if (!arg)
        return 0;

    errno = 0;
    *begin = strtoull(arg, &rest, 0);
    if (errno)
        return -1;

    if (!*rest)
        return 0;

    if (*rest != '-')
        return -1;

    *end = strtoull(rest+1, &rest, 0);
    if (errno || *rest)
        return -1;

    return 0;
}
static int load_file(uint8_t **buffer, size_t *size, char *arg,
        const char *prog)
{
    uint64_t begin_arg, end_arg;
    uint8_t *content;
    size_t read;
    FILE *file;
    long fsize, begin, end;
    int errcode;
    char *range;

    if (!buffer || !size || !arg || !prog) {
        fprintf(stderr, "%s: internal error.\n", prog ? prog : "");
        return -1;
    }

    range = strstr(arg, ":");
    if (range) {
        range += 1;
        range[-1] = 0;
    }

    errno = 0;
    file = fopen(arg, "rb");
    if (!file) {
        fprintf(stderr, "%s: failed to open %s: %d.\n",
                prog, arg, errno);
        return -1;
    }

    errcode = fseek(file, 0, SEEK_END);
    if (errcode) {
        fprintf(stderr, "%s: failed to determine size of %s: %d.\n",
                prog, arg, errno);
        goto err_file;
    }

    fsize = ftell(file);
    if (fsize < 0) {
        fprintf(stderr, "%s: failed to determine size of %s: %d.\n",
                prog, arg, errno);
        goto err_file;
    }

    begin_arg = 0ull;
    end_arg = (uint64_t) fsize;
    errcode = parse_range(range, &begin_arg, &end_arg);
    if (errcode < 0) {
        fprintf(stderr, "%s: bad range: %s.\n", prog, range);
        goto err_file;
    }

    begin = (long) begin_arg;
    end = (long) end_arg;
    if ((uint64_t) begin != begin_arg || (uint64_t) end != end_arg) {
        fprintf(stderr, "%s: invalid offset/range argument.\n", prog);
        goto err_file;
    }

    if (fsize <= begin) {
        fprintf(stderr, "%s: offset 0x%lx outside of %s.\n",
                prog, begin, arg);
        goto err_file;
    }

    if (fsize < end) {
        fprintf(stderr, "%s: range 0x%lx outside of %s.\n",
                prog, end, arg);
        goto err_file;
    }

    if (end <= begin) {
        fprintf(stderr, "%s: bad range.\n", prog);
        goto err_file;
    }

    fsize = end - begin;

    content = malloc(fsize);
    if (!content) {
        fprintf(stderr, "%s: failed to allocated memory %s.\n",
                prog, arg);
        goto err_file;
    }

    errcode = fseek(file, begin, SEEK_SET);
    if (errcode) {
        fprintf(stderr, "%s: failed to load %s: %d.\n",
                prog, arg, errno);
        goto err_content;
    }

    read = fread(content, fsize, 1, file);
    if (read != 1) {
        fprintf(stderr, "%s: failed to load %s: %d.\n",
                prog, arg, errno);
        goto err_content;
    }

    fclose(file);

    *buffer = content;
    *size = fsize;

    return 0;

err_content:
    free(content);

err_file:
    fclose(file);
    return -1;
}

static int load_pt(struct pt_config *config, char *arg, const char *prog)
{
    uint8_t *buffer;
    size_t size;
    int errcode;

    errcode = load_file(&buffer, &size, arg, prog);
    if (errcode < 0)
        return errcode;

    config->begin = buffer;
    config->end = buffer + size;

    return 0;
}

static int diag(const char *errstr, uint64_t offset, int errcode)
{
    if (errcode)
        printf("[%" PRIx64 ": %s: %s]\n", offset, errstr,
                pt_errstr(pt_errcode(errcode)));
    else
        printf("[%" PRIx64 ": %s]\n", offset, errstr);

    return errcode;
}

/* State flags */
int got_pip, got_pad, got_vmcs, pad_cnt, pkt_cnt = 0;

/* JSONify the output */
FILE* fp = NULL;

static int dump_bundle(uint64_t offset, const struct pt_packet *packet,
        const struct pt_config *config)
{
    int errcode;

    switch (packet->type){
        case ppt_pip:
            if (got_pip == 0)
            {
                fprintf(fp, "\t{\n");
                fprintf(fp, "\t\t\"packet\": [\n");
                fprintf(fp, "\t\t\t{\n\t\t\t\t\"id\": \"PIP\","
                        "\n\t\t\t\t\"payload\": %"PRIx64","
                        "\n\t\t\t\t\"nr\": %d\n\t\t\t},\n",
                        packet->payload.pip.cr3, packet->payload.pip.nr);

                got_pip = 1;
            }
            return 0;

        case ppt_pad:
            if ((got_pip == 1) && (pad_cnt < 8))
            {
                pad_cnt++;
            }
            if (pad_cnt == 8)
            {
                pad_cnt = 0;
                got_pad = 1;
            }
            return 0;

        case ppt_vmcs:
            if ((got_pad == 1) && (got_pip == 1))
            {
                fprintf(fp, "\t\t\t{\n\t\t\t\t\"id\": \"VMCS\","
                        "\n\t\t\t\t\"payload\": %"PRIx64"\n\t\t\t},\n", 
                        packet->payload.vmcs.base);
                got_vmcs = 1;
            }
            return 0;

        case ppt_tsc:
            if ((got_pip == 1) && (got_vmcs == 1))
            {
                fprintf(fp, "\t\t\t{\n\t\t\t\t\"id\": \"TSC\","
                        "\n\t\t\t\t\"payload\": %"PRIx64"\n\t\t\t}\n", 
                        packet->payload.tsc.tsc);
                got_pip = 0;
                got_vmcs = 0;
                fprintf(fp, "\t\t]\n\t},\n");
            }
            return 0;
    }

}

static int dump_packets(struct pt_packet_decoder *decoder,
        const struct pt_config *config)
{
    uint64_t offset;
    int errcode;

    offset = 0ull;
    for (;;) {
        struct pt_packet packet;

        errcode = pt_pkt_get_offset(decoder, &offset);
        if (errcode < 0)
            return diag("error getting offset", offset, errcode);

        errcode = pt_pkt_next(decoder, &packet, sizeof(packet));
        if (errcode < 0) {
            if (errcode == -pte_eos)
                return 0;

            return diag("error decoding packet", offset, errcode);
        }

        errcode = dump_bundle(offset, &packet,
                config);
        if (errcode < 0)
            return errcode;
    }
}

static int dump_sync(struct pt_packet_decoder *decoder,
        const struct pt_config *config)
{
    int errcode;

    errcode = pt_pkt_sync_set(decoder, 0ull);
    if (errcode < 0)
        return diag("sync error", 0ull, errcode);
    errcode = pt_pkt_sync_forward(decoder);
    if (errcode < 0)
        return diag("sync error", 0ull, errcode);

    for (;;) {
        errcode = dump_packets(decoder, config);
        if (!errcode)
            break;

        errcode = pt_pkt_sync_forward(decoder);
        if (errcode < 0)
            return diag("sync error", 0ull, errcode);

    }

    return errcode;
}

static int dump(const struct pt_config *config)
{
    struct pt_packet_decoder *decoder;
    int errcode;

    decoder = pt_pkt_alloc_decoder(config);
    if (!decoder)
        return diag("failed to allocate decoder", 0ull, 0);

    errcode = dump_sync(decoder, config);

    pt_pkt_free_decoder(decoder);
    return errcode;
}


int main(int argc, char *argv[])
{
    struct pt_config config;
    int errcode, idx;
    char *ptfile;

    ptfile = NULL;

    memset(&config, 0, sizeof(config));
    pt_config_init(&config);

    for (idx = 1; idx < argc; ++idx) {
        if (strncmp(argv[idx], "-", 1) != 0) {
            ptfile = argv[idx];
            if (idx < (argc-1))
                return usage(argv[0]);
            break;
        }
    }

    if (!ptfile)
        return no_file_error(argv[0]);

    errcode = pt_cpu_errata(&config.errata, &config.cpu);
    if (errcode < 0)
        diag("failed to determine errata", 0ull, errcode);

    errcode = load_pt(&config, ptfile, argv[0]);
    if (errcode < 0)
        return errcode;

    fp = fopen("bundles.json", "w+");
    fprintf(fp, "\"bundle\": [\n");
    errcode = dump(&config);
    fprintf(fp, "]\n");
    fclose(fp);

    free(config.begin);

    return -errcode;
}
