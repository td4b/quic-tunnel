#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include "server.h"
#include "client.h"
#include <stdbool.h>
#include "shared.h"
#include "tun.h"

#ifndef DEBUG_MODE
#define DEBUG_MODE false 
#endif

/* Program documentation */
const char* argp_program_version = "quictun 1.0";
const char* argp_program_bug_address = "edwin.twest@gmail.com";
static char doc[] = "Quic tunneling and routing via msquic.";

/* The options we understand */
static struct argp_option options[] = {
    {"server", 's', "IP", 0, "Specify server IP address"},
    {"port", 'p', "PORT", 0, "Specify server port"},
    {"client", 'c', 0, 0, "Run in client mode instead of server mode default"},
    {0} // End of options
};

/* Used to communicate with `main` */
struct arguments {
    char* server_ip;
    int port;
    int client_mode;
};

/* Parse a single option */
static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    struct arguments* arguments = state->input;

    switch (key) {
    case 's':
        arguments->server_ip = arg;
        break;
    case 'p':
        arguments->port = atoi(arg);
        break;
    case 'c':
        arguments->client_mode = 1;
        break;
    case ARGP_KEY_END:
        if (!arguments->server_ip || arguments->port == 0) {
            argp_usage(state); // Print usage and exit
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

/* `argp` parser setup */
static struct argp argp = { options, parse_opt, 0, doc };

int main(int argc, char** argv) {

    struct arguments arguments;

    arguments.server_ip = NULL;
    arguments.port = 0;
    arguments.client_mode = 0;

    initialize_msquic();

    /* Parse arguments */
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    /* Call the appropriate function */
    if (arguments.client_mode) {
        configure_tun_interface_client("tun0client");
        start_client(arguments.server_ip, arguments.port);
    }
    else {
        configure_tun_interface_server("tun0server");
        start_server(arguments.server_ip, arguments.port);
    }

    return 0;
}

