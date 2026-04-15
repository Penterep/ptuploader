[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


## PTUPLOADER - The Tool for testing uploads in web apps


## Installation

```
pip install ptuploader
```

## Adding to PATH
If you're unable to invoke the script from your terminal, it's likely because it's not included in your PATH. You can resolve this issue by executing the following commands, depending on the shell you're using:

For Bash Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

For ZSH Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshrc
source ~/.zshrc
```

## Usage examples
```
PTUPLOADER -u http://example.com/upload.php -r requestfile.txt -P file -s http://www.example.com/uploads/ -ts EXT
```

## Options
```
-v    --version                       Show script version and exit
-h    --help                          Show this help message and exit
-j    --json                          Output in JSON format
-vv   --verbose                       Enable verbose mode

-ua   --user-agent   <user-agent>     Set User-Agent header
-c    --cookie       <cookie>         Set Cookie(s)
-t    --threads      <threads>        Set thread count (default: 10)
-H    --headers      <header:value>   Set custom header(s)
-p    --proxy        <proxy>          Set Proxy

-u    --url          <url>            Target upload URL
-f    --file         <filename>       File to upload
-sz   --size         <size>           Size of uploaded file
-n    --number       <number>         Number of uploaded files
-e    --extensions   <extensions>     Extensions of uploaded files
-l    --language     <language>       Target language (PHP, ASP, JSP, NET, PY, JS)

-T    --type         <type>           Upload type: MULTIPART (default, others in development)
-ct   --content-type <mimetype>       Content-Type of uploaded file (e.g. image/jpeg)

-r    --request      <request>        Raw request file or base64 request (headers included)
-d    --data         <data>           Custom request data
-P    --parameter    <parameter>      Parameter to test (e.g. file, upload, POST param)

-s    --storage      <url_to_dir>     URL to uploaded files directory
-w    --wordlist     <file>           Custom wordlist file for storage path discovery
-sy   --string-yes   <string>         Required string in response for success
-sn   --string-no    <string>         Forbidden string in response for success

-ts   --tests        <test>           Select test type:
                                     ANTIVIR      Detect antivirus presence
                                     FINDSTORAGE  Find uploaded file via dictionary attack
                                     MAXSIZE      Max file size limit
                                     COUNT        Max file count limit
                                     EXT          Allowed extensions (+ execution test)
                                     CHARS        Allowed filename characters
                                     EXEC         Execution bypass techniques
                                     ADS          Alternate Data Streams
                                     TRAVERSAL    Path traversal vulnerability
                                     CONTENT      File content validation
                                     CT           Content-Type validation
                                     XXE          XXE vulnerability
                                     ZIPBOMB      Zip bomb vulnerability
```

## Dependencies
```
ptlibs
```

## External tools
None at this moment.


## License

Copyright (c) 2025 Penterep Security s.r.o.

ptuploader is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ptuploader is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptuploader. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!