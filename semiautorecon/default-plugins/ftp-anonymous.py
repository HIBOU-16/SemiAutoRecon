from semiautorecon.plugins import ServiceScan
import ftplib
import os

class FtpAnonymousTest(ServiceScan):
    
    def __init__(self):
        super().__init__()
        self.name = "FTP Anonymous Test"
        self.tags = {'default', 'safe', 'ftp'}

    def configure(self):
        self.match_service_name('ftp')

    async def run(self, service):
        if service.protocol != 'tcp':
            print('It is a tcp service.')
        if service.protocol == 'tcp':
            try:
                ftp_address = service.target.address
                ftp = ftplib.FTP(ftp_address)
                ftp.login("anonymous", "")
                # Print a success message if login is successful
                print("Anonymous login successful ")
                # You can perform further actions here, such as listing directories or downloading files
                directories = ftp.nlst()
                scandir = os.path.join(service.target.scandir, service.protocol + str(service.port))
                dir_path = os.path.join(scandir, "ftp_from_dir.txt")
                with open(dir_path, "w") as file:
                    file.write("user: anonymous\n")
                    file.write("password: \n")
                    file.write("Login successful\n\n")
                    # You can perform further actions here, such as listing directories or downloading files
                    directories = ftp.nlst()
                    for directory in directories:
                        file.write(directory + "\n")
                    # Print a message indicating that directories have been written to the file
                    print(f"Directories found have been written to {dir}")
                # Remember to close the FTP connection when done
                ftp.quit()
            except Exception as e:
                # Print an error message if login fails
                print("Anonymous login failed ")
