#!/bin/bash
#Part 1 
echo ''
echo "=========================================="
echo "    WF_PROJECT, ENJOY :)   "
echo "=========================================="
echo ''
function usercheck ()  #Check if the User are Root.
{
USER=$(id -u)
if [ "$USER" == "0" ]
then
echo "Your now A Root USER, please wait"
echo ''
else
echo "This script must be run as root." 
exit 1 # Changed exit to exit 1 for clarity on error.
fi
}
usercheck
#Part2
function FILECHECK()
{
echo "Please Enter any file to analyze: "
echo ''
read FILEMEM 
echo ''
if [ -f "$FILEMEM" ]
then
echo "Great! Now the System running the needed Tools...."
echo ''
else 
echo "The file name is not what it's supposed to be"
exit 
fi
}
FILECHECK
#Part3
function TOOLKIT_PREP()
{
for MODULE in strings binwalk bulk_extractor foremost 
do
CHECK=$(command -v $MODULE)
if [ -z "$CHECK" ] # -z if the value is empty
then
echo 'The Tool is not installed:' $MODULE # MODULE value is these Tools strings binwalk bulk_extractor foremost.
echo 'Begin the install'
sudo apt-get install $MODULE &>/dev/null #Configure the command to run silently without displaying output
else
echo 'The following Tool is installed' $MODULE 
fi
done
}
TOOLKIT_PREP
#Part4
function forensic_carve ()
{
mkdir -p ExtractedFiles #Main Folder
echo ''
echo "[*]Running bulk_extractor..." #Bulk Extractor Directory
bulk_extractor "$FILEMEM" -o ExtractedFiles/DataOfBulk > /dev/null 
echo ''
echo "[*]Running foremost..."
mkdir -p ExtractedFiles/FormostData #Foremost Directory
foremost -i "$FILEMEM" -t all -o ExtractedFiles/FormostData > /dev/null
echo ''
echo "[*] Running binwalk..."
mkdir -p ExtractedFiles/DataOfBinwalk
echo ''
binwalk -e  --run-as=root "$FILEMEM" -C ExtractedFiles/DataOfBinwalk > /dev/null 2>&1 #Binwalk Directory 
echo ''
mkdir -p DataOfStrings #Create a directory for Strings
strings "$FILEMEM" |grep -i exe > DataOfStrings/exe_data.txt
strings "$FILEMEM" |grep -i password > DataOfStrings/password_data.txt
strings "$FILEMEM" |grep -i username > DataOfStrings/username_data.txt
echo ''
echo 'The files now at the ExtractedFiles Folder, please go at check it up '
echo ''
}
forensic_carve

#Part5
function PACKETS_DATA ()
{
PCAP_F=$(find ExtractedFiles -type f -name "*.pcap" 2>/dev/null | head -n 1)     # Variable for the path of the Pcap File if exist.
Size_F=$(ls -l "$PCAP_F" 2>/dev/null | awk '{print $5}')        #The Size of the Pcap File.
if [ -z "$PCAP_F" ]
then 
echo "Pcap File Is not Exist"
else 
echo 'the path of Pcap File is:' "$PCAP_F"
echo 'the Size of the Pcap File is:' "$Size_F"
echo ''
echo ''
fi
}
PACKETS_DATA
#Part6
function checkvol ()
{
echo "Is your file A memory File? (y/n)"
read ANSWER
if [ "$ANSWER" == "y" ]
then
echo "Volatility installation is running in the background..."
# Start installation process at the Background...
wget https://github.com/volatilityfoundation/volatility/releases/download/2.6.1/volatility_2.6_lin64_standalone.zip &> /dev/null
unzip -j volatility_2.6_lin64_standalone.zip volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone &> /dev/null
rm volatility_2.6_lin64_standalone.zip
mv volatility_2.6_lin64_standalone vol

sudo chmod 700 vol 

mkdir -p Volatility_DATA
mkdir -p Registry

OS=$(./vol -f "$FILEMEM" imageinfo 2>/dev/null | grep "Suggested Profile" | head -1 | cut -d':' -f2 | cut -d',' -f1 | xargs)   #Variable for the OS of the Mem File.

echo "Collecting process list..." 
PROCESSES=$(./vol -f $FILEMEM --profile="$OS" pslist 2>/dev/null)   #Variable for the Processes at the same time the meme got captured.

echo "Collecting network connections..." 
NETWORK=$(./vol -f $FILEMEM --profile="$OS" netscan 2>/dev/null)    #Variable for the IP's and Ports who was running at the same time.

echo "Dumping registry hives..." 
REG_LIST=$(./vol -f $FILEMEM --profile="$OS" dumpregistry --dump-dir Registry 2>/dev/null) #Variable for export the Registry Files from the same time the mem got captured.

echo "The OS of the mem File is: $OS" > Volatility_DATA/Operation.txt
echo "These are the running processes: $PROCESSES" > Volatility_DATA/Processes.txt
echo "The network connections are: $NETWORK" > Volatility_DATA/Network.txt
else
echo 'The selected file is not a valid memory dump'
rm vol
echo ''
echo ''
echo 'Now all the relevant Files at your Vol Folder Path.'
fi
}
checkvol
#sudo rm -r ExtractedFiles        # command to remove Folders without permissions

#Part7
function display_statistics()
{
echo ''
(
echo "=========================================="
echo "    WINDOWS FORENSICS ANALYSIS REPORT    "
# Count files found in each directory
BULK_FILES=$(find ExtractedFiles/DataOfBulk -type f 2>/dev/null | wc -l)
FOREMOST_FILES=$(find ExtractedFiles/FormostData -type f |wc -l 2>/dev/null)  
BINWALK_FILES=$(find ./ExtractedFiles/DataOfBinwalk -type f | wc -l 2>/dev/null)
STRING_FILES=$(find DataOfStrings -type f 2>/dev/null | wc -l)
TOTAL_FILES=$(find ExtractedFiles -type f 2>/dev/null | wc -l)
echo '==========================================='
echo 'Correct time:' $(date)
echo "The OS System is:" $OS
echo '==========================================='
echo "-some Carved Files Found:" $TOTAL_FILES
echo "-Bulk Extractor Files:" $BULK_FILES
echo "-Foremost Files:" $FOREMOST_FILES
echo "-Binwalk Files:" $BINWALK_FILES
echo '==========================================='
echo "-Total Files Extracted:" $TOTAL_FILES
echo '==========================================='
echo "-String results Analysis Files:" $STRING_FILES
echo '==========================================='
echo 'Pcap Full Path and Size:'
echo "-Path:" $PCAP_F
echo "-Size:" $Size_F
echo '==========================================='
TOTAL_FILES=$((BULK_FILES + FOREMOST_FILES + BINWALK_FILES + STRING_FILES))

# If memory analysis exists
if [ -d "volatility_DATA" ]
then
# Count files found in each directory
VOL_DATA=$(find volatility_DATA -type f 2>/dev/null | wc -l)
REG_DATA=$(find registry -type f 2>/dev/null | wc -l)

echo "-volatility_DATA Files:" $VOL_DATA
echo "-registry Files:" $REG_DATA
fi
# Saves output to txt file
) | tee Report.txt
echo "================================================================================================================================================================"
echo "Now the Memory File is ready for analysis.."
echo "================================================================================================================================================================"
echo 'Now please go to your relevant Folder wait couple of seconds, All the files should be at WF_PROJECT.ZIP Please check it up, and you will fin the Report.txt file'
echo "================================================================================================================================================================"
### ARCHIVE ALL FILES AFTER ALL PROCESSES ARE COMPLETE ###
zip -r WF_PROJECT.zip ExtractedFiles Volatility_DATA DataOfStrings Registry Report.txt > /dev/null
sudo rm -r ExtractedFiles Volatility_DATA DataOfStrings Registry vol Report.txt tmagen773631.s22NX201.sh
}
display_statistics

