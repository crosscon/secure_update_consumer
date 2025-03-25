#include "suit_platform.h"

#include "mbedtls/error.h"
#include "mbedtls/x509.h"
#include "mbedtls/pem.h"
#include "mbedtls/pk.h"

#include <string.h>    /* strcmp */
#include <stdio.h>     /* printf */
#include <stdlib.h>    /* exit */
#include <fcntl.h>     /* O_BINARY */
#include <unistd.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>  /* mmap */
#include <getopt.h>

// Command identifiers
#define CMD_NONE                0
#define CMD_VALIDATE_MANIFEST   1
#define CMD_EXTRACT_SBOM        2
#define CMD_EXTRACT_PROPERTIES  3
#define CMD_EXTRACT_IMAGE       4
#define CMD_INSTALL_IMAGE       5
#define CMD_HELP                6

// Print tool usage information
void print_usage(const char *argv0)
{
    printf("Usage: %s COMMAND MANIFEST_FILE [OPTIONS]\n\n", argv0);
    printf("Commands:\n");
    printf("  validate-manifest   Validate the SUIT manifest\n");
    printf("  extract-sbom        Extract Software Bill of Materials\n");
    printf("  extract-properties  Extract update properties\n");
    printf("  extract-image       Extract update image\n");
    printf("  install-image       Install update image\n");
    printf("  help                Show this help message\n");
    printf("\nOptions:\n");
    printf("  --key=PEM_FILE     Specify PEM file containing public key for signature verification\n");
}

// Parse the command string and return the corresponding command identifier
int parse_command(const char *cmd)
{
    if (strcmp(cmd, "validate-manifest") == 0) return CMD_VALIDATE_MANIFEST;
    if (strcmp(cmd, "extract-sbom") == 0) return CMD_EXTRACT_SBOM;
    if (strcmp(cmd, "extract-properties") == 0) return CMD_EXTRACT_PROPERTIES;
    if (strcmp(cmd, "extract-image") == 0) return CMD_EXTRACT_IMAGE;
    if (strcmp(cmd, "install-image") == 0) return CMD_INSTALL_IMAGE;
    if (strcmp(cmd, "help") == 0) return CMD_HELP;
    
    return CMD_NONE; // Unknown command
}

int main(int argc, char **argv)
{

    int selected_command = CMD_NONE;
    char *manifest_name = NULL;
    char *key_file = NULL;
    int rc = 0;
    
    // Check if we have enough arguments
    if (argc < 2) {
        printf("Missing command\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    // Parse the command
    selected_command = parse_command(argv[1]);

    // Check if we have a manifest file
    if (argc < 3) {
        printf("Missing manifest file argument\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    
    // Get the manifest filename
    manifest_name = argv[2];
    
    // Check for optional --key parameter
    for (int i = 3; i < argc; i++) {
        char *arg = argv[i];
        if (strncmp(arg, "--key=", 6) == 0) {
            key_file = arg + 6;  // Point to the part after "--key="
        }
    }
    
    // Load the public key if specified
    if (key_file) {
        printf("Using public key from: %s\n", key_file);
        if (load_public_key_from_pem(key_file) != 0) {
            printf("Failed to load public key from %s\n", key_file);
            exit(EXIT_FAILURE);
        }
    }

    // Open the manifest file
    int manifest_fd = -1;
    struct stat st;

    if ((manifest_fd = open(manifest_name, O_RDONLY)) < 0) {
        perror("Error in file opening");
        exit(EXIT_FAILURE);
    }

    if (fstat(manifest_fd, &st) < 0) {
        perror("Error in fstat");
        close(manifest_fd);
        exit(EXIT_FAILURE);
    }

    uint8_t *mfst_ptr;
    if ((mfst_ptr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, manifest_fd, 0)) == MAP_FAILED) {
        perror("Error in mmap");
        close(manifest_fd);
        exit(EXIT_FAILURE);
    }

    // Handle the command
    switch (selected_command) {
        case CMD_VALIDATE_MANIFEST:
            printf("Manifest parsing and validation\n");
            int rc = TA_CROSSCON_VALIDATE_MANIFEST(mfst_ptr, st.st_size);
            if (rc != 0) {
                printf("Manifest validation failed\n");
                exit(EXIT_FAILURE);
            } else {
                printf("Manifest validation successful\n");
            }
            break;

        case CMD_EXTRACT_SBOM:
            printf("Extracting update SBOM\n");
            uint8_t *sbom = TA_CROSSCON_GET_SBOM(mfst_ptr, st.st_size);
            if (sbom) {
                printf("SBOM: %s\n", sbom);
            } else {
                printf("Failed to extract SBOM\n");
            }
            break;
            
        case CMD_EXTRACT_PROPERTIES:
            printf("Extracting properties from manifest\n");
        
            // First get the count of properties to allocate memory
            size_t prop_count = TA_CROSSCON_GET_PROPERTIES(mfst_ptr, st.st_size, NULL);
            if (prop_count > 0) {
                // Allocate memory for the array of strings
                char **properties = (char**)malloc(prop_count * sizeof(char*));
                if (properties == NULL) {
                    printf("Failed to allocate memory for properties array\n");
                    break;
                }
                
                // Get the actual property strings
                prop_count = TA_CROSSCON_GET_PROPERTIES(mfst_ptr, st.st_size, properties);
                
                // Print all properties
                printf("Found %zu properties:\n", prop_count);
                for (size_t i = 0; i < prop_count; i++) {
                    printf("Property %zu: %s\n", i+1, properties[i]);
                }
                
                // Free the memory
                for (size_t i = 0; i < prop_count; i++) {
                    free(properties[i]);
                }
                free(properties);
            } else {
                printf("No properties found in manifest\n");
            }
            break;
            
        case CMD_EXTRACT_IMAGE:
            printf("Extracting or fetching image from the manifest\n");
            uint8_t *image = NULL;
            size_t image_size = 0;

            // Extract the image and its size
            rc = TA_CROSSCON_GET_IMAGE(mfst_ptr, st.st_size, &image, &image_size);
            if (rc == 0 && image != NULL) {
                printf("Image extracted successfully (%zu bytes)\n", image_size);
                
                // Save the image to a file if needed
                const char *output_file = "/out/images/update.bin";
                FILE *file = fopen(output_file, "wb");
                if (file) {
                    fwrite(image, 1, image_size, file);
                    fclose(file);
                    printf("Image saved to %s\n", output_file);
                } else {
                    printf("Failed to save image to file\n");
                }

                // Free the allocated memory for the image
                free(image);
            } else {
                printf("Failed to extract image\n");
            }
            
            break;
            
        case CMD_INSTALL_IMAGE:
            printf("Installing image\n");
            rc = TA_CROSSCON_INSTALL_IMAGE(NULL, 0);
            if (rc != 0) {
                printf("Failed to install image\n");
            }
            break;
            
        case CMD_HELP:
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
            
        case CMD_NONE:
        default:
            printf("Unknown command: %s\n", argv[1]);
            print_usage(argv[0]);
            exit(EXIT_FAILURE);
    }
   
    // Clean up
    munmap(mfst_ptr, st.st_size);
    close(manifest_fd);
    cleanup_resources();
    
    exit(EXIT_SUCCESS);
}