#!/bin/bash

TEST_FOLDER="./test"

# number of testcase
num_of_testcase=4

# Run test and redirect output to file
./sdb < "${TEST_FOLDER}/testcase1.txt" > "${TEST_FOLDER}/out1.txt" 2>&1
./sdb sample/hello64 < "${TEST_FOLDER}/testcase2.txt" > "${TEST_FOLDER}/out2.txt" 2>&1
./sdb sample/hello64 < "${TEST_FOLDER}/testcase3.txt" > "${TEST_FOLDER}/out3.txt" 2>&1
./sdb sample/hello64 < "${TEST_FOLDER}/testcase4.txt" > "${TEST_FOLDER}/out4.txt" 2>&1

# define regular expression of each testcase
declare -A regex_array1
regex_array1[3]="^\*\* pid [0-9]{1,5}$"
regex_array1[4]="^([0-9a-f]{16})-([0-9a-f]{16})\s+(r-x)\s+(0)\s+.*sample/hello64$"
regex_array1[5]="^([0-9a-f]{16})-([0-9a-f]{16})\s+(rw-)\s+(0)\s+.*sample/hello64$"
regex_array1[6]="^([0-9a-f]{16})-([0-9a-f]{16})\s+(rw-)\s+(0)\s+\[stack\]$"
regex_array1[7]="^([0-9a-f]{16})-([0-9a-f]{16})\s+(r--)\s+(0)\s+\[vvar\]$"
regex_array1[8]="^([0-9a-f]{16})-([0-9a-f]{16})\s+(r-x)\s+(0)\s+\[vdso\]$"
regex_array1[9]="^([0-9a-f]{16})-([0-9a-f]{16})\s+(--x)\s+(0)\s+\[vsyscall\]$"
regex_array1[13]="^\*\* child process [0-9]{1,5} terminated normally \(code 0\)$"

declare -A regex_array2
regex_array2[2]="^\*\* pid [0-9]{1,5}$"
regex_array2[6]="^RDI\s+(0)\s+RSI\s+(0)\s+RBP\s+(0)\s+RSP\s+([0-9a-f]{1,16})\s+$"

declare -A regex_array3
regex_array3[12]="^\*\* pid [0-9]{1,5}$"

declare -A regex_array4
regex_array4[12]="^\*\* pid [0-9]{1,5}$"
regex_array4[19]="^\*\* child process [0-9]{1,5} terminated normally \(code 0\)$"

# declare -A regex_array5

# function to compare output file and answer file
# return value
#    0: success
#    1: compare fail
#    2: line count of 2 files are mismatch
compare_files() {
    local file1="$1"
    local file2="$2"
    declare -n regex_array="$3"

    local result=0
    # compare line count of 2 files
    local line_count_file1=$(wc -l < "$file1")
    local line_count_file2=$(wc -l < "$file2")

    if [ "$line_count_file1" -ne "$line_count_file2" ]; then
        # echo "line count mismatch"
        return 2
    fi

    # compare 2 files line by line
    local line_number=1
    while IFS= read -r line1 && IFS= read -r line2 <&3; do
        if [[ ${regex_array[$line_number]} ]]; then
            # compare by regex expression
            if ! [[ $line1 =~ ${regex_array[$line_number]} ]] || ! [[ $line2 =~ ${regex_array[$line_number]} ]]; then
                echo "diff at line $line_number"
                echo "output: $line1"
                echo "expect: $line2"
                result=1
            fi
        else
            # compare string directly
            if [[ "$line1" != "$line2" ]]; then
                echo "diff at line $line_number"
                echo "output: $line1"
                echo "expect: $line2"
                result=1
            fi
        fi

        line_number=$((line_number + 1))
    done < "$file1" 3< "$file2"

    return $result
}

# Verify testcase
pass_cnt=0
for (( i=1; i <= num_of_testcase; i++ )); do
    file1="${TEST_FOLDER}/out${i}.txt"
    file2="${TEST_FOLDER}/out${i}-ans.txt"

    echo "--------------------- testcase${i} ---------------------"
    compare_files "$file1" "$file2" "regex_array${i}"
    result=$?

    if [ "$result" -eq 0 ]; then
        echo "testcase${i}: pass"
        pass_cnt=$((pass_cnt + 1))
    elif [ "$result" -eq 1 ]; then
        echo "testcase${i}: fail"
    else
        echo "testcase${i}: line count mismatch"
    fi
done

# Output test result
echo "======================= TEST RESULT ======================="
echo "test $num_of_testcase cases, $pass_cnt pass, $(($num_of_testcase - $pass_cnt)) fails"

if [[ $num_of_testcase -ne $pass_cnt ]]; then
    exit 1
else
    # if test all pass, delete the outout files and exit with code 0
    find test -type f -regextype grep -regex 'test\/out[0-9]\+.txt' -delete
    exit 0
fi
