#Prints the help text which explains briefly how to use the script.
def print_help():
    help_text = """
    Options:
        -h, --help            show this help message and exit
        1                     validate IPs from a file
        2                     validate URLs/Domains from a file
        3                     validate Hashes from a file
        4                     validate Bulk IOCs from a file
        5                     exit the script

    For Bulk IOCs:
        The script expects a text file with IOCs to be categorized and separated by a colon.
        Example:
        IPs:
        1.1.1.1
        8.8.8.8
        Hashes:
        abc123...
        def456...
        URLs/Domains:
        example.com
        anotherexample.com

    FYI.
    Script auto-weaponizes IOCs for validation and gives output files where IOCs are deweaponized.

    FYI.
    I made this script as part of Python project for IOC validation.
    """
    print(help_text)