#include <iostream>

using namespace std;

class Base {
     public:
            virtual void f() { cout << "Base::f" << endl; }
            virtual void g() { cout << "Base::g" << endl; }
            virtual void h() { cout << "Base::h" << endl; }
 
};



int main()
{
typedef void(*Fun)(void);

	Base b;

	Fun pFun = NULL;

	cout << "虚函数表地址：" << (long*)(&b) << endl;
	cout << "虚函数表 — 第1个函数地址：" << ((long*)*(long*)(&b)+0) << endl;
	cout << "虚函数表 — 第2个函数地址：" << ((long*)*(long*)(&b)+1) << endl;
	cout << "虚函数表 — 第3个函数地址：" << ((long*)*(long*)(&b)+2) << endl;
	cout << "虚函数表 — 第4个函数地址：" << ((long*)*(long*)(&b)+3) << endl;

	// Invoke the first virtual function  
	pFun = (Fun)*((long*)*(long*)(&b)+0);
	pFun();

	pFun = (Fun)*((long*)*(long*)(&b)+1);
	pFun();

	pFun = (Fun)*((long*)*(long*)(&b)+2);
	pFun();
	
	pFun = (Fun)*((long*)*(long*)(&b)+3);
	if(pFun)
	{
		pFun();
	}


}


