// SPDX-License-Identifier: GPL-2.0-or-later
// Link stubs for the browser core. Replaces the object nasomers/flycast-wasm ships prebuilt with no source.
// Written for this project from the symbols and behaviour of that object (35cac15b...), so the core's complete source is here.
// Built by build-network.sh. See NOTICE.md.
#include <stddef.h>
#include <string.h>

#define GL_VERSION 0x1F02u
#define GL_SHADING_LANGUAGE_VERSION 0x8B8Cu

const unsigned char *__real_glGetString(unsigned int name);

// The frontend's file-name helpers, without the rest of its file library: the base name, cut at its extension.
static void short_name(char *out, const char *in, size_t size)
{
    if (!out || !size)
        return;
    *out = 0;
    if (!in)
        return;
    const char *base = in;
    for (const char *p = in; *p; p++)
        if (*p == '/' || *p == '\\')
            base = p + 1;
    strncpy(out, base, size - 1);
    out[size - 1] = 0;
    char *dot = strrchr(out, '.');
    char *slash = strrchr(out, '/');
    if (dot && dot > slash)
        *dot = 0;
}

void fill_short_pathname_representation(char *out, const char *in, size_t size)
{
    short_name(out, in, size);
}

void fill_short_pathname_representation_noext(char *out, const char *in, size_t size)
{
    short_name(out, in, size);
}

// No block manager to reset in this configuration.
void bm_Reset(void)
{
}

// WebGL's own strings would make the core choose a desktop GL path (linked with -Wl,--wrap=glGetString).
const unsigned char *__wrap_glGetString(unsigned int name)
{
    if (name == GL_VERSION)
        return (const unsigned char *)"OpenGL ES 3.0 WebGL 2.0";
    if (name == GL_SHADING_LANGUAGE_VERSION)
        return (const unsigned char *)"OpenGL ES GLSL ES 3.00";
    return __real_glGetString(name);
}
