# IOC VALIDATOR 
# V1 VirusTotal, AbuseIPDB and MalwareBazaar interaction.
#
import sys
import os
#This line imports the print_help function from a module named common_utils, which is located within a package called utils. 
#The print_help function is likely used to display help messages to the user.
from utils.common_utils import print_help
# This line is importing several functions from the ioc_functions module, which is part of the ioc_processing package. 
# These functions are probably related to the processing of Indicators of Compromise (IOCs) in cybersecurity
from ioc_processing.ioc_functions import (
    validate_iocs,
    parse_bulk_iocs,
    bulk_analysis,
    process_individual_ioc_file,
    perform_bulk_analysis
)
from file_operations.file_utils import (
    read_file,
    clean_input
)

def main():
     # Set up directories for input and output files relative to the script's location.
    script_directory = os.path.dirname(os.path.realpath(__file__))
    input_directory = os.path.join(script_directory, 'input_files')
    output_directory = os.path.join(script_directory, 'output_files')
    show_help = False
 # Check if help was requested via command-line arguments.
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        show_help = True

    while True:
          # If help is requested, display it and reset the flag.
        if show_help:
            print_help()
            show_help = False  
            continue  
# Validate IOCs and get the user's choice for the next action.
        choice = validate_iocs()
     # If no valid choice is made, prompt again.
        if choice is None:
            continue
 # Exit the script if the user chooses to do so.
        if choice == '5':
            sys.exit("\nExiting script.")
 # If the user chooses bulk analysis, prompt for file names and perform the analysis.
        if choice == '4':
            file_name = input('Please provide the name of the txt file for Bulk IOCs: ')
            output_file_name = input('Please provide the name of the output file for Bulk IOC results: ')
            file_path = os.path.join(input_directory, file_name)
            output_file_path = os.path.join(output_directory, output_file_name)
            content = read_file(file_name)
            cleaned_content = clean_input(content)
            iocs = parse_bulk_iocs(cleaned_content)
            perform_bulk_analysis(iocs, output_file_path)
 # If the user chooses individual analysis, prompt for file names and perform the analysis based on IOC type.
        elif choice in ['1', '2', '3']:
            ioc_type = {'1': 'ips', '2': 'urls', '3': 'hashes'}[choice]
            file_name = input(f'Please provide the name of the txt file for {ioc_type.upper()}: ')
            output_file_name = input('Please provide the name of the output file for IOC results: ')
            file_path = os.path.join(input_directory, file_name)
            output_file_path = os.path.join(output_directory, output_file_name)
            iocs = process_individual_ioc_file(file_name, ioc_type)
            perform_bulk_analysis(iocs, output_file_path)
    # If an invalid option is chosen, prompt the user again.
        else:
            print("\nInvalid option, please select again.")
# Entry point of the script.
if __name__ == "__main__":
    main()