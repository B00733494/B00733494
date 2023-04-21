#!/usr/bin/env python
# coding: utf-8

# # Import Libraries

# In[1]:


#pip install -U --pre pycaret


# In[1]:


from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib import request, error
import pandas as pd
import re
from pycaret.clustering import *
import urllib.parse
import sys
import warnings
warnings.filterwarnings("ignore")


# # Import Datasets

# In[2]:


text=pd.read_csv("text - text.csv") # This file uploads the sql injection payloads
http = pd.read_csv(r'allmixed.csv') 


# # Define Functions

# In[3]:


class SimpleHTTPProxy(SimpleHTTPRequestHandler):
    proxy_routes = {}

    @classmethod
    def set_routes(cls, proxy_routes):
        cls.proxy_routes = proxy_routes

    def do_GET(self):
        parts = self.path.split('/')
        # print (parts)
        live_data = ExtractFeatures(parts[3])
        result = predict_model(kmeans, data=live_data)
        #print(result['Cluster'][0])
        if result['Cluster'][0] == "Cluster 1":
            print('Intrusion Detected')
            self.send_response(302)
            self.send_header('Location', 'https://www.google.com/')
            self.end_headers()
        if len(parts) >= 2:
            self.porxy_request('http://' + parts[2] + '/')
        else:
            super().do_GET()
            

    def porxy_request(self, url):
        try:
            response = request.urlopen(url)
        except error.HTTPError as e:
            # print ('error')
            self.send_response_only(e.code)
            self.end_headers()
            return

        self.send_response_only(response.status)
        for name, value in response.headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.copyfile(response, self.wfile)


# In[4]:


def ExtractFeatures(path):
    path = urllib.parse.unquote(path)
    badwords_count = 0
    single_q = path.count("'")
    double_q = path.count("\"")
    dashes = path.count("--")
    braces = path.count("(")
    spaces = path.count(" ")
    for word in badwords:
        badwords_count += path.count(word)
        lst = [single_q,double_q,dashes,braces,spaces,badwords_count]
        print (lst)
        return pd.DataFrame([lst],columns = ['single_q','double_q','dashes','braces','spaces','badwords'] )


# # Find Unique words from payload dataset

# In[5]:


# Create a set to store the unique words
unique_words = set()

# Iterate over each row in the DataFrame
for index, row in text.iterrows():
    
    # Get the payload for this row
    payload = row['PAYLOAD']
    
    # Find all the words in the payload
    words = re.findall(r'\w+', payload)
    
    # Add the words to the set of unique words
    unique_words.update(words)
bad_words_final=sorted(list(unique_words)) # storing unique words
print(list(unique_words))


# In[6]:


final_bad_words_list = [element.lower() for element in bad_words_final] + [element.upper() for element in bad_words_final]
print(final_bad_words_list) #uppercase and lowercase badwords alltogether


# In[7]:


badwords = final_bad_words_list
clu1 = setup(data = http, normalize = True, numeric_features = ['single_q','double_q','dashes','braces','spaces'] ,ignore_features = ['method','path','body','class'])
kmeans = create_model('kmeans', num_clusters = 2)


# # Cluster Plot

# In[8]:


plot = plot_model(kmeans, plot='cluster', scale=1, save=True)
plot_model(kmeans, plot='cluster');


# In[ ]:


proxy_route = input("Enter proxy route: ")
if proxy_route == "":
    proxy_route = 'http://demo.testfire.net/' #default route
host = input("Enter Proxy ip: ") #127.0.0.1
if host == "":
    host = "127.0.0.1" #default host
port = input("Enter Port Number: ")
if port == "":
    port = "5555" #default port

SimpleHTTPProxy.set_routes({'proxy_route': proxy_route})
with HTTPServer((host, int(port)), SimpleHTTPProxy) as httpd:
    host, port = httpd.socket.getsockname()
    print(f'Listening on http://{host}:{int(port)}')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received, exiting. ")


# In[ ]:




