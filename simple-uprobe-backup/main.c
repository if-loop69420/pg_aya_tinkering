#include <stdio.h>


void print_user_message(char* user_message) {
  printf("The user said:\n%s\n",user_message);
}

int main(){
  char input_buf[256];

  while(0<1) {
      fgets(input_buf, 256, stdin);
      print_user_message(input_buf);
  }
}
