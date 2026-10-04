#include <stdio.h>
#include <unistd.h>
int main(){
  printf("Process started!\n");
  printf("My PID is: %d\n",getpid());
  sleep(30);
  printf("Process finished.\n");
  return 0;
}
