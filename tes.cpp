#include <bits/stdc++.h>

class A {
public:
	A() {};
	~A() {
		std::cout << "DESTRUKTOR" << std::endl;
	}
};

int main() {
	std::unique_ptr<A> a = std::make_unique<A>();
	for (int i = 1; i <= 1000000000; ++i) {
		std::cout << i << std::endl;
		if (i == 1000000)
			break;
	}
}