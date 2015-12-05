#include <stdio.h>
#include <curl/curl.h>
 
int main(int argc, char**argv)
{
  CURL *curl;
  CURLcode res;
  if(argc != 2) return;
  curl = curl_easy_init();
  while(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, argv[1]);
    /* example.com is redirected, so we tell libcurl to follow redirection */ 
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
 
    /* Perform the request, res will get the return code */ 
    res = curl_easy_perform(curl);
    /* Check for errors */ 
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
 
    /* always cleanup */ 
  }

  curl_easy_cleanup(curl);
  return 0;
}
