import os
from colorama import Fore, Style

def show_banner():
    """
    Shows the application banner.
    """
    try:
        terminal_width = os.get_terminal_size().columns
    except (OSError, AttributeError):
        try:
            import subprocess
            terminal_width = int(subprocess.check_output(['stty', 'size']).split()[1])
        except (subprocess.SubprocessError, ValueError, IndexError, FileNotFoundError):
            try:
                import shutil
                terminal_width = shutil.get_terminal_size().columns
            except (AttributeError, ValueError):
                terminal_width = 100

    if terminal_width < 80:
        banner = f"""
{'=' * (terminal_width - 2)}
{'DNSGapHunter':^{terminal_width}}
{'DNS Security Testing Tool':^{terminal_width}}
{'=' * (terminal_width - 2)}
        """
    else:
        banner = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣠⠤⠤⢤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠶⠋⠉⣻⠿⠿⠟⠿⠛⠛⠛⠛⠛⠛⠒⠒⠒⠋⠁⢩⣳⣶⡶⠶⡶⢶⠶⣶⣶⣤⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣤⣤⡴⠶⢶⣾⣿⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣤⡴⣳⡞⠁⣤⣥⣾⣿⣿⣿⣿⣿⣆⠀
⠀⠀⠀⠀⠀⠀⣀⣀⣠⣤⣤⠤⠴⠖⠚⢿⡿⣿⣍⣉⣋⣹⣎⠙⠻⣷⣷⣿⣯⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⡿⠛⠋⠛⠃⣸⣿⡿⢿⣿⣿⡏⠛⠹⣿⡆
⠀⠀⠀⣠⣴⣾⡿⣟⢻⣷⣤⣀⣀⣠⣤⣤⣷⣿⣷⣶⣶⣶⣿⡶⣶⣿⡟⣿⣻⡆⠘⡆⢲⠈⢁⣀⣀⣀⣀⡤⠿⠿⢿⣖⢒⣚⣋⢉⡽⢷⣀⣸⣿⣿⣿⡆⢠⣿⡇
⠀⠀⣰⣿⣿⣧⠀⠉⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠛⠛⡛⣻⡇⠀⢸⡋⢻⣿⣇⠀⢿⣿⣻⣿⠟⣟⡏⡗⡶⡶⡒⡟⢿⡟⡟⡼⣫⣹⣸⣿⣽⣯⣿⣿⣷⠁⣿⡇
⢰⣿⣿⣿⣿⣙⣾⣦⣞⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⡇⢾⢿⣷⣼⣷⡟⠀⢨⣿⣿⣿⡄⣸⣹⣿⣽⣼⣽⣼⣼⣾⣷⣿⣷⣶⣿⣿⣿⣿⣿⣿⣯⣾⡿⠁
⠈⠉⠻⣿⣿⣏⡉⠉⢩⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⣀⣸⣿⣿⣿⡇⢠⡟⡛⠛⠛⠃⠬⠿⠛⠛⣿⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠉⠀⠀⠀
⠀⠀⠀⠙⠛⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠉⣹⣿⣿⣿⣿⣤⣼⣿⣷⣖⡒⠒⢒⡒⢚⠛⢻⣷⣬⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠉⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠀⠀⠀⠈⠙⠛⠛⠛⠉⠉⠉⠛⠋⠉⠛⢻⣟⣿⡟⠻⣿⣿⣿⣿⣿⡿⠇⠀⠀⢠⣿⣿⣿⣿⣿⣿⡿⠿⠟⠛⠉⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⣰⡿⣿⠞⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⢹⡟⣿⣿⡀⠀⠀⢀⣀⣀⣴⠋⢱⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠻⠿⣯⣴⣿⣿⣿⣿⣧⡾⣾⠋⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢹⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣧⡯⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⠞⠯⠀⡤⠖⠛⠉⠈⠙⠻⢿⣿⣿⣿⡿⠿⠟⠛⢛⣉⣩⣭⠷⠿⢷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼⠻⢦⣀⠚⠄⠀⠀⠀⠀⠀⠂⠀⠉⠻⠤⠴⠒⣚⣋⣉⣥⣴⣶⣾⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠎⢀⣴⠃⠈⠙⠳⢤⣄⡠⠀⣇⠀⣀⣠⣤⣶⣶⣿⣿⣿⣯⣿⣷⣿⣿⣍⣹⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠃⣠⡾⠃⠀⠀⢩⠄⠀⠀⠉⡉⠉⢳⣻⣿⣿⣿⣿⣿⣿⡿⠿⢟⣛⣻⡭⠭⠖⠛⢃⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣇⢰⣧⣄⡀⠀⡰⠃⠀⠀⢀⠞⠀⠀⠀⢿⣛⣻⡭⠭⠷⠒⠚⠉⠉⢀⣀⣠⣤⣤⣶⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣯⣙⢦⡞⠁⠀⠀⢠⠋⠀⠀⠀⠀⠈⢁⣀⣠⣤⣴⣶⣶⠿⠿⠟⣛⣋⣹⡉⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣷⣦⣤⣤⣧⣤⣴⣶⣶⣿⡿⠟⢻⣿⣿⡟⠀⠀⣶⣶⣾⣿⣿⣿⣷⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠉⠀⣾⣿⣿⫿⣿⣿⣿⣶⣶⣾⣿⣿⠿⠿⠛⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢿⣿⣿⣿⣿⣿⣶⣶⣿⣿⣿⠿⠿⠟⠛⠋⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢙⢛⠛⠛⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    """
    
    banner_lines = banner.strip().split('\n')
    centered_banner = []
    
    for line in banner_lines:
        line_length = len(line)
        if line_length > terminal_width:
            line = line[:terminal_width-3] + "..."
            line_length = terminal_width
        
        padding = (terminal_width - line_length) // 2
        centered_line = ' ' * padding + line
        centered_banner.append(centered_line)
    
    centered_banner = '\n'.join(centered_banner)
    
    tool_info = "DNSGapHunter | A DNS Security Testing Tool | v1.0"
    
    if len(tool_info) > terminal_width:
        tool_info = tool_info[:terminal_width-3] + "..."
    
    tool_info_padding = (terminal_width - len(tool_info)) // 2
    
    print(f"{Fore.CYAN}{centered_banner}{Style.RESET_ALL}")
    print(f"{' ' * tool_info_padding}{Fore.YELLOW}{tool_info}{Style.RESET_ALL}") 