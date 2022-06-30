int bar2(int a, int b);

int foo2(int a, int b) {
	if (a == 0 || b == 0)
		return 0;
	a--;
	b--;	
	return a+b + bar2(a,b);
}

int bar2(int a, int b) {
 if (a == 0 || b == 0)
		return 0;
	
	return 1+ foo2(a,b);
}

int main () {

 int x = bar2(2,2);
 int y = foo2(2,2);
 
 return 0;
}
