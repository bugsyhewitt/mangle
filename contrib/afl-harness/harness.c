/*
 * mangle AFL++ persistent-mode harness — reference template.
 *
 * Built with `afl-clang-fast` this is a persistent-mode harness; built with
 * plain gcc it falls back to a single-iteration binary (useful for
 * smoke-testing the build chain without AFL++ installed).
 *
 * In the inner loop:
 *   1. AFL writes one candidate input file to the path passed as argv[1].
 *   2. We shell out to `mangle afl-mutate --seed <argv[1]> --mutator <NAME>`,
 *      which writes the grammar-aware mutant to its stdout.
 *   3. We pipe that stdout into the decoder under test (default: ffmpeg) and
 *      let AFL's edge-coverage instrumentation in the decoder do its work.
 *
 * This is a *reference template* — short and easy to read. A production
 * harness would:
 *   - Drive `libavcodec` directly via the C API rather than spawning ffmpeg.
 *   - Reuse one mangle subprocess in a long-running co-process pipe rather
 *     than fork+exec per iteration.
 *   - Vary --mutator across iterations (the env var is a stopgap).
 *
 * Compile:
 *   make CC=afl-clang-fast
 *
 * Run (under afl-fuzz, with a corpus directory ./seeds/):
 *   AFL_AUTORESUME=1 afl-fuzz -i seeds/ -o out/ -- ./mangle-afl-harness @@
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* When built with afl-clang-fast, __AFL_LOOP is provided by the AFL runtime
 * and gives us persistent-mode behaviour. Under plain gcc we degrade to a
 * single-iteration binary so the build chain can be tested without AFL++. */
#ifdef __AFL_HAVE_MANUAL_CONTROL
#  define AFL_LOOP(N) __AFL_LOOP(N)
#  define AFL_INIT()  __AFL_INIT()
#else
#  define AFL_LOOP(N) (loop_once_var ? loop_once_var-- : 0)
#  define AFL_INIT()  do { } while (0)
   static int loop_once_var = 1;
#endif

/* Default config — override by env var so a single binary can drive ffmpeg
 * or libde265 without recompilation. */
static const char *
getenv_or(const char *name, const char *fallback)
{
    const char *v = getenv(name);
    return (v && *v) ? v : fallback;
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "usage: %s <seed-path-or-@@>\n"
                "  mangle afl-mutate driver — AFL replaces @@ with the candidate "
                "path.\n"
                "env vars:\n"
                "  MANGLE_MUTATOR   mutator name (default: sps-dimensions)\n"
                "  MANGLE_SEED_RNG  RNG seed for the mutation (default: 0)\n"
                "  DECODER          decoder argv0 (default: ffmpeg)\n",
                argv[0]);
        return 2;
    }

    AFL_INIT();

    const char *mutator   = getenv_or("MANGLE_MUTATOR", "sps-dimensions");
    const char *seed_rng  = getenv_or("MANGLE_SEED_RNG", "0");
    const char *decoder   = getenv_or("DECODER", "ffmpeg");

    while (AFL_LOOP(10000)) {
        /* Pipe: mangle afl-mutate --seed argv[1] --mutator NAME | decoder - */
        int mangle_to_decoder[2];
        if (pipe(mangle_to_decoder) != 0) {
            perror("pipe");
            return 1;
        }

        pid_t mangle_pid = fork();
        if (mangle_pid == 0) {
            /* mangle child — stdout -> pipe write end */
            close(mangle_to_decoder[0]);
            dup2(mangle_to_decoder[1], STDOUT_FILENO);
            close(mangle_to_decoder[1]);
            execlp("mangle", "mangle", "afl-mutate",
                   "--seed", argv[1],
                   "--mutator", mutator,
                   "--seed-rng", seed_rng,
                   (char *)NULL);
            perror("execlp mangle");
            _exit(127);
        }

        pid_t decoder_pid = fork();
        if (decoder_pid == 0) {
            /* decoder child — stdin <- pipe read end */
            close(mangle_to_decoder[1]);
            dup2(mangle_to_decoder[0], STDIN_FILENO);
            close(mangle_to_decoder[0]);
            /* ffmpeg form: read raw HEVC from stdin, decode, discard output. */
            execlp(decoder, decoder, "-v", "error",
                   "-f", "hevc", "-i", "pipe:0",
                   "-f", "null", "-",
                   (char *)NULL);
            perror("execlp decoder");
            _exit(127);
        }

        /* parent — close both pipe ends, wait for both children */
        close(mangle_to_decoder[0]);
        close(mangle_to_decoder[1]);

        int status;
        waitpid(mangle_pid, &status, 0);
        waitpid(decoder_pid, &status, 0);
        /* AFL scores the decoder's edge coverage via its instrumentation;
         * we just need to have exercised the decoder this iteration. */
    }

    return 0;
}
