
https://os.cybbh.io/public/os/latest/index.html








- 👋 Hi, I’m @bilybobthorton
- 👀 I’m interested in ...
- 🌱 I’m currently learning ...
- 💞️ I’m looking to collaborate on ...
- 📫 How to reach me ...

<!---
bilybobthorton/bilybobthorton is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->



persistant mechanisms
&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&windows persistance
powershell profiles
alternate data streams in txt



&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&linux persistance


test-path -path $profile.currentusercurrenthost
test-path -path $profile.currentuserallhosts
test-path -path $profile.alluserscurrenthost
test-path -path $profile.allusersallhosts
telling you if the current user is set like when they log in theyre no ps1 thats being ran no configuration
if one of these returns true you read the file
$profile.alluserallhosts
new-item -itemtype file -path $profile -force
creates a new profil
ise $profile
opens powershell with new profile



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%transcripts
start-transcript c:\users\student\Desktop\MondayPS.txt
creates a transcript can be usefule in civilian sector

http://10.50.24.129:8000/teams/join
TRKI-M-001

My STACK ID
10.50.43.24
xfreerdp /u:andy.dwyer /v:10.50.43.24 /dynamic-resolution +glyph-cache +clipboard  
douthits box  10.50.42.234
cash is 10.50.34.149
crank is 10.50.46.40

ssh -J andy.dwyer@10.50.43.24 bombadil@10.2.0.7



with open(firstfile) as inf:
	with open(second,file 'w') as outf:
		outf.write(inf.read())
		
		
	
	
tion = 'abcdefg'
ary = {}    ### this makes a dictionary 
for i in tion:
	ary[i] = i

				steps through assigning i as a
ary

    
    
The textfile, travel_plans.txt, contains the summer travel plans for someone with some commentary. Find the total number of characters in the file and save to the variable num.
10/13/2023, 1:56:05 PM - 11 of 11
1

filename = 'travel_plans.txt'

2

filename = open(filename, 'r')

3

num = 0

4

for i in filename:

5

    num += len(i)
    
    
    
    
    
    


We have provided a file called emotion_words.txt that contains lines of words that describe emotions. Find the total number of words in the file and assign this value to the variable num_words.
10/13/2023, 2:03:11 PM - 8 of 8

1

filename = 'emotion_words.txt'

2

filename = open(filename, 'r')

3

data = filename.read()

4

words = data.split()

5

num_words = len(words)







Assign to the variable num_lines the number of lines in the file school_prompt.txt.
10/13/2023, 2:06:48 PM - 5 of 5

1

filename = 'school_prompt.txt'

2

filename = open(filename, 'r')

3

num_lines = len(filename.readlines())





Challenge: Using the file school_prompt.txt, assign the third word of every line to a list called three.
10/13/2023, 2:15:44 PM - 3 of 3

1

with open('school_prompt.txt', 'r') as fileref:

2

    three = [line.split()[2] for line in fileref]

3

print(three)

4

​




Challenge: Create a list called emotions that contains the first word of every line in emotion_words.txt.
10/13/2023, 2:24:51 PM - 5 of 5

1

filename = 'emotion_words.txt'

2

with open(filename, 'r') as f:

3

    emotions = [line.split(None, 1)[0] for line in f]
    
    
    
    

Assign the first 33 characters from the textfile, travel_plans.txt to the variable first_chars.
10/13/2023, 2:27:13 PM - 2 of 2

1

filename = 'travel_plans.txt'

2

with open(filename, 'r') as fp:

3

    first_chars = fp.read(33)

4

​

apropos bash                 #### shows some bash shell commands
find -iname /filename        ####looks for files
find / -name student 	      ####looks for files by the user
find / -name passwd -maxdepth 2   ####looks for passwd with max depth of 2 in directory  
find / -executable ! -type d ####looks for executable that is not directory
egrep "student|root" /etc/passwd



###brace expression

preamble{braceexpression}postamble
example
touch ~/file{1..5}.txt       #### makes five files named file 1,2,3,4,5 frome ~/ or home ,filepath can change
ps -u student		      #### shows what processes student is using
ps -u student --forest       #### shows relationship between processes running in tree format
ps aux			      #### shows who ran it what they ran and where they ran it
killall chrome		      #### kills everything related to process
cut 			      #### used to cut sections of a file
less /etc/password |cut -d/ -f1   ####cut out the first feild and use delimeter
echo "Destroy lonely is trash" | cut -c1-7    #### returns destroy
echo "Destroy lonely is trash" | cut -d" " -f2 -complement

https://linuxopsys.com/topics/bash-chain-operators-in-linux
tail /etc/passwd | awk -F: '{print$1}'
less /etc/passwd | awk -F: '($3 >= 150){print $0}'  #### will print the uid if it is above 150
if $0 is changed to 1,$3,$6 it will print out name id and homepath
less /etc/passwd | awk -F: 'BEGIN {OFS="#"}{print $1,$3,$6}'

sort sorts with the ascii value
less sort.txt |awk -F" " '{print $1}' | uniq -c 


#!/bin/bash
if [[ condition ]]; then 
	commands
elif [[ condition ]]; then 
	commands
else 
fi


#!/bin/bash
if [[ 3129 == $((15645/5 )) ]]; then 
        echo "The Math is Mathin"
elif [[3129 != $((15645/6 )) ]]; then 
        echo "Math is no good"
fi 


find $HOME/1123 -name *.txt
sed '/^p/d'		#### shows all lines starting with p
sed -e 		#### lets you do multiple things at once


LCPL=e3
echo $LCPL
a=10
b=5
expr $a - $b
c=$(expr $a - $B)


dmesg | grep -iE "CPU|BIOS" | grep -ivE "usable|reserved" | sed -E 's/\[[0-9]+\.[0-9]+\] //' | less

#!/bin/bash
mkdir -p $HOME/ZIP
echo -n "12345" | md5sum | cut -d ' ' -f1 > $HOME/ZIP/file1
echo -n "6789" | md5sum | cut -d ' ' -f1 > $HOME/ZIP/file2
echo -n "abcdef" | md5sum | cut -d ' ' -f1 > $HOME/ZIP/file3
(cd $HOME/ZIP && zip -j $HOME/ZIP/file.zip file1 file2 file3)
(cd $HOME/ZIP && tar czf $HOME/ZIP/file.tar.gz -C $HOME/ZIP file.zip)



mkdir -p $HOME/ZIP
echo -n "12345" | md5sum | cut -d ' ' -f1 > $HOME/ZIP/file1
echo -n "6789" | md5sum | cut -d ' ' -f1 > $HOME/ZIP/file2
echo -n "abcdef" | md5sum | cut -d ' ' -f1 > $HOME/ZIP/file3
(cp $HOME/ZIP/* $HOME/ZIP/ && zip -j $HOME/ZIP/file.zip $HOME/ZIP/file1 $HOME/ZIP/file2 $HOME/ZIP/file3)
(cd $HOME/ZIP && tar czf $HOME/ZIP/file.tar.gz file.zip)







#!/bin/bash

dirname="path/to/directory"
if [ ! -d "$dirname" ]; then
  echo "Invalid Directory"
  exit 1
fi
file_count=$(find "$dirname" -maxdepth 1 -type f | wc -l)

echo "Number of files in '$dirname' (excluding '.' and '..'): $file_count"





QUESTION 1

Incorrect
AssertionError: Lists differ: ['127.0.0.1 localhost', '::1 localhost ip6-localhost[138 chars]2d2'] != ['127.0.0.1\tlocalhost', '::1\tlocalhost ip6-localho[145 chars]2d2']
First differing element 0:
'127.0.0.1 localhost'
'127.0.0.1\tlocalhost'

function q1()
{
  filename=$1
  while read line; do
    if [[ ! $line =~ ^\s*$|^#.* ]]; then
      echo $line
    fi
  done < "$filename"
}



question 2
function q1()
{
  #Valid Variables are:
  logs=$1
  archive=$2
  tar -czvf $archive $(find $logs -name "*.log")
}


question 3
function q1()
{
  searchdir=$1
  output=$2
  grep -ilr "CRITICAL" --include "*.txt" $searchdir > $output
}


question 4


function q1()
{
  dirlist=$1
  total=0
  for dir in $dirlist
  do
    if [ -d $dir ]
    then
      num_files=$(ls -p $dir | grep -v / | wc -l)
      total=$((total+num_files))
    fi
  done
  echo $total
}

question 5 


function q1()
{
  dirdel=$1
  if [ -d $dirdel ]
  then
    cd $dirdel
    rm -f *
  fi
}



question 6
function q1()
{
  newfile=$1
  touch $newfile
  touch -t $(date +"%Y")06140830 $newfile
}



question 7

function q1()
{
  filename=$1
  if [ -f $filename ]
  then
    content=$(cat $filename)
    case "$content" in
      "abc") echo "123";;
      "def") echo "789";;
      "xyz") echo "000";;
      *) echo "Error";;
    esac
  fi
}



question 8 

function q1()
{
  src=$1
  dst=$2
  match=$3
  if [ -f $src ]
  then
    grep "$match" $src > $dst
  fi
}



question 9 
function q1()
{
  var=$1
  pids=$(ps aux | grep $var | awk '{print $2}')
  for pid in $pids
  do
    kill -9 $pid
  done
}



question 10
function q1()
{
  dirpath=$1
  find $dirpath -type f -mmin -60 | sort > temp.txt
  while read line
  do
    echo $line
  done < temp.txt
  rm temp.txt
}




#######################find cmdlets
To update the help system in PowerShell, run the command: Update-Help

The cmdlets that deal with viewing/manipulating processes are: Get-Process, Stop-Process, and Start-Process.

To display a list of services installed on your local computer, run the command: Get-Service

The cmdlets used to write or output objects or text to the screen are: Write-Output, Write-Host, and Out-Default.

The cmdlets that can be used to create, modify, list, and delete variables are: Set-Variable, New-Variable, Get-Variable, and Remove-Variable.

The cmdlet that can be used to find and list other cmdlets, other than Get-Help, is: Get-Command.

The cmdlet used to prompt the user for input is: Read-Host.

#########################running cmdlets
To display a list of running processes, run the command: Get-Process

To display a list of all running processes that start with the letter "s", run the command: Get-Process s*

The cmdlet and its purpose for the following aliases are:
- gal: Get-Alias
- dir: Get-ChildItem
- echo: Write-Output
- ?: Where-Object
- %: ForEach-Object
- ft: Format-Table
4. To display a list of Windows Firewall Rules, run the command: Get-NetFirewallRule
5. To create a new alias called "gh" for the cmdlet "Get-Help", run the command: New-Alias -Name gh -Value Get-Help.

##############################variables 
1  $var1 = Get-Random -Minimum 25 -Maximum 51

2. $var2 = Get-Random -Minimum 1 -Maximum 11

3. $sum = $var1 + $var2

4. $sub = $var1 - $var2

5. $prod = $var1 * $var2

6. $quo = $var1 / $var2

7." $var1 + $var2 = $sum"

8."$var1 - $var2 = $sub"

9. "$var1 * $var2 = $prod"

10."$var1 / $var2 = $quo"

#############################reverse arrays 
$start = Get-Random -10..0
$end = Get-Random 1..20
if ($start -gt $end) {
    $start, $end = $end, $start
}
$array = $start..$end
$reversedArray = $array[-1..-$array.Count]

C:\> $array
PS C:\> $reversedArray

##############################hash tables
$employee1 = @{
    "First" = "Mary"
    "Last" = "Hopper"
    "ID" = "001"
    "Job" = "Software Developer"
    "Username" = ("$($employee1.First[0])$($employee1.Last)$($employee1.ID)").ToLower()
    "Status" = "Management"
}


$employee2 = @{
    "First" = "John"
    "Last" = "Williams"
    "ID" = "002"
    "Job" = "Web Developer"
    "Status" = "Intermediate"
}

$employee1.Job = "Software Lead"

$employee3 = @{
    "First" = "Alex"
    "Last" = "Moran"
    "ID" = "003"
    "Job" = "Software Developer"
    "Status" = @{
        "Mary" = "Management"
        "John" = "Intermediate"
        "Alex" = "Entry Level"
    }
}

######################################the pipeline
1. Display the start time of the earliest and latest running processes:
Get-Process | Sort-Object StartTime | Select-Object -First 1 StartTime
Get-Process | Sort-Object StartTime -Descending | Select-Object -First 1 StartTime

2. Identify a cmdlet that returns the current date and time then using this cmdlet and Select-object, display only the current day of the week:

Get-Date | Select-Object -ExpandProperty DayOfWeek


3. Identify a cmdlet that displays a list of installed hotfixes:

Get-Hotfix

4. Extend the expression to sort the list by install date, and display only the install date and hotfix ID:

Get-HotFix | Sort-Object InstalledOn | Select-Object InstalledOn, HotFixID

5. Extend the expression further, but this time sort by description, include description, hotfix ID, and install Date:

Get-HotFix | Select-Object InstalledOn, HotFixID, Description | Sort-Object Description


######################################custom object 
$computer_system = Get-WmiObject Win32_ComputerSystem | Select-Object Manufacturer,Name
$bios = Get-WmiObject Win32_BIOS | Select-Object SerialNumber
$operating_system = Get-WmiObject Win32_OperatingSystem | Select-Object Caption,Version
$logical_disks = (Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID).DeviceID
$host_system = New-Object PSObject -Property @{
    'ComputerName' = $computer_system.Name
    'OperatingSystem' = $operating_system.Caption
    'Version' = $operating_system.Version
    'Manufacturer' = $computer_system.Manufacturer
    'Disks' = ($logical_disks | ForEach-Object { '\\\\' + $computer_system.Name + '\\root\\cimv2:Win32_LogicalDisk.' + $_ })
}
$host_system
################################3#####comparison and condition
$line1 = "Do you have model number: MT5437 for john.doe@sharklasers.com?"
$line2 = "What model number for john.doe@sharklasers.com?"

# Function to extract the model number from a line of text
function Get-ModelNumber($line) {
    $modelNumber = $line -match "model number: (\w+)"
    if ($modelNumber) {
        return $Matches[1]
    }
    else {
        return "Model number not found"
    }
}

# Check line 1 for model number
$line1Result = Get-ModelNumber $line1

# Check line 2 for model number
$line2Result = Get-ModelNumber $line2

# Print the results
if ($line1Result -ne "Model number not found") {
    "Line 1: $($line1Result)"Functions

    Write
}
else {
    "Line 1: $($line1Result)"
}

if ($line2Result -ne "Model number not found") {
    "Line 2: $($line2Result)"
}
else {
    "Line 2: $($line2Result)"
}
#######################################looping and iteration
$processes = @("notepad", "msedge", "mspaint")
$processes | ForEach-Object { Start-Process $_ }
Start-Sleep -Seconds 5
Get-Process $processes | Select-Object Id, ProcessName, StartTime, CPU, WorkingSet | Sort-Object Id
########################################create functions 

# Function to get the ordinal date of the current date
function Get-OrdinalDate {
    $date = Get-Date
    $ordinal = [System.Globalization.CultureInfo]::CurrentCulture.Calendar.GetDayOfYear($date)
    return "$($date.Year)-$($ordinal.ToString("00"))"
}

# Function to get the square of a number
function Get-SquareNum($num) {
    return $num*$num
}

# Function to get the product of three numbers
function Get-Product($num1, $num2, $num3) {
    return $num1*$num2*$num3
}


#########################################function parameters

function Get-Hypotenuse {
    Param (
        [Parameter(Mandatory=$true)]
        [int]$a,
        [Parameter(Mandatory=$true)]
        [int]$b
    )

    $c = [math]::sqrt(($a * $a) + ($b * $b))
    return $c
}

function Get-MissingAngle {
    Param (
        [Parameter(Mandatory=$true)]
        [int]$a,
        [Parameter(Mandatory=$true)]
        [int]$b
    )

    $c = 180 - $a - $b
    return $c
}

function Get-PersonInfo {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$FirstName,
        [Parameter(Mandatory=$true)]
        [string]$LastName,
        [Parameter(Mandatory=$true)]
        [int]$Age,
        [Parameter(Mandatory=$true)]
        [int]$Weight
    )

    $weight_kg = [math]::round($Weight / 2.2)
    $personInfo = @{ 
        "first" = $FirstName
        "last" = $LastName
        "age" = $Age
        "weight" = $weight_kg
    }

    return $personInfo
}

############################################ADVANCED REGEX
function Get-MultiSum([int[]]$Array, [int]$ExcludeInt) {
    $sum = 0
    foreach ($val in $Array) {
        if ($val -ne $ExcludeInt) {
            $sum += $val
        }
    }
    return $sum
}



function Get-LongestName {
    $stateNames = @()
    for ($i=1; $i -le 3; $i++) {
        $stateName = Read-Host "Enter name of state #$i"
        $stateNames += $stateName
    }
    $stateNames | Sort-Object -Property Length -Descending | ForEach-Object { 
        Write-Host "$_: $($_.Length)" 
    }
}


##################################################regex
function Get-NetInfo {
    $nic = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True'
    $ip = $nic.IPAddress[0]
    $subnet = $nic.IPSubnet[0]
    $gateway = $nic.DefaultIPGateway[0]
    Write-Host "IP: $ip"
    Write-Host "Subnet: $subnet"
    Write-Host "Gateway: $gateway"
}


function Get-URLInfo {
    $filePath = "dns.txt"
    $urlRegex = "(http|https)://[a-zA-Z0-9./?=_-]*"
    $urlCount = 0
    $urlList = @()

    # read file and extract URLs using regex
    Get-Content $filePath | ForEach-Object {
        foreach ($match in [regex]::Matches($_, $urlRegex)) {
            $urlList += $match.Value
            $urlCount++
        }
    }

    # output results
    Write-Host "URLs found: $urlCount"
    $urlList | Group-Object | ForEach-Object {
        Write-Host "$($_.Name): $($_.Count)"
    }
}


function q3 {
    $max_str = ""
    while ($true) {
        $input_str = Read-Host "Enter a string"
        if ($input_str.Length -eq 0) {
            break
        }
        if ($input_str.Length -gt $max_str.Length) {
            $max_str = $input_str
        }
    }
    return $max_str
}



 instances

ssh student@bottomlinuxip -X
password is password
terminator  lets you split window and rename heading 
git clone https://git.cybbh.space/programming/python/public.git
ls shows us a lower case public folder
cd public/
ls activities/

in home directory 
vim .vimrc 

-------
syntax enable 
set tabstop=4
set shiftwidth=4
set expandtab
set number
filetype indent on
set autoindent 
-------
:wq!


python3
make sure it is python 3
>>> is the repl


invoke use
python3 myscript.py

bool-boolean true or false
int-integers
float -floating point decimal
str-string

tuple -immutable sequence of items🤖️
list -mutable sequence of items🤖️

addition+
subtraction-
multiplication*
division/
integer division//
modulus%
exponent**

single quotes: 'allows embedded "double" quotes'
double quotes: "allows embedded 'single' quotes"

'The ciwwviys are going to win the {}.'.format('superbowl')


'PE = {:.2f}'.format(3.14159265359)






>>>a = 1
>>>a
1
>>>b=2
>>>a + b 
3
>>>type(a)
<class 'int'>
>>>a = 1.1
>>>a
1.1
>>>type(a)
<class 'float'>
>>>c = a + b 
>>>c
3.1
>>>a = 'cat'
>>>type(a)
<class 'str'>

>>>a = 1
>>>b = 2.4
>>>c = "string"
>>>d = true
>>>e = [1,2,3]
>>>f = (1,2,3)
>>>type(a)
int
>>>float(a)
1.0
>>>type(a)
float
>>>
>>>
>>>f= list(f)
>>>f
[1,2,3]
>>>type(f)
list
>>>a = tuple(a)
>>>
>>>e = list(e)
>>>type(e)
list
>>>[]=list
>>>()==tuple
------------------------------
>>>a = [1,2,3]
>>>a[1]
2
>>>b = (3,4,5)
>>>b[2]
5
>>>
>>>c
e returned.
def q8(address):
 93 def q8(address):




   
    
