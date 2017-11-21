#!/bin/sh
#filename: get_filed_match.sh
##功能：获取字段匹配项

echo test file is: $1

TFILE=$1
FINDLIST=findlist

export COL1=`cat $TFILE | awk -F, '{print $2}' | sort|uniq | head -n 1`
echo COL1 is $COL1

CMPSEQ=7
cat $TFILE | awk -v SEQ=$CMPSEQ -F, '{print $SEQ}' | sort | uniq  > $FINDLIST

while read LINE
do
	echo "===============>> file line is : " $LINE
	export COL2=`echo $LINE`
	##此处可能查找不正确，因为此处的内容有可能被修改掉了，所以$2不一定与之前的相同了
	##解决办法是，两个逗号之间的内容添加"" 双引号包含，防止sort 或uniq 或cat 造成内容丢失
	cat $TFILE | awk  -v SEQ=$CMPSEQ  -F , '{if( $SEQ == ENVIRON["COL2"] ) print }' 

	echo
	echo
	echo
done < $FINDLIST
# cat $TFILE | awk -F , '{if( $2 == ENVIRON["COL1"] ) print}' 




echo done!!!
echo done!!!
echo done!!!