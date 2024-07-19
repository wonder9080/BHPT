simple loop in bash script


#! /bin/bash 



for n1 in {2020..2024}
do
  echo $n1; 
done

for n in {2020..2024}/{01..12}/{01..31}
do 
  echo $n1/$n2/$3;
done 


echo "Bash version ${BASH_VERSION}"


C styled loops 
n=2025
for (( i=2020 ; i<=$n ; i++ ));
do 
  echo $i;
done

# ./loop.sh  intead of sh loop.sh
# different results because you needto execute with bash loop.sh  