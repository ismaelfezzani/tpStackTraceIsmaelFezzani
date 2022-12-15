import pandas as pd
import pprint
import time 
from datetime import timedelta

#create a panda dataframe with the csv dataset
file = pd.read_csv("Iot NetWork Intrusion Dataset.csv")

#function which will swap the emplacement of two column in the pandas dataframe passed in parameter  
def swapColumns(file,col1,col2):
    
    
    col_list=list(file.columns)
    x,y=col_list.index(col1),col_list.index(col2)
    col_list[y],col_list[x]=col_list[x],col_list[y]
    file=file[col_list]

    return file

#modify the date format from the csv to include only the the date 
def setTimestamp(file):
    for val in file["Timestamp"]:
        file["Timestamp"].replace(val,val.split(" ")[0])
    print(file["Timestamp"])




#implemetation of the Finally algorith, adapted to the context of the exercice 
#
def finallyAnomaly(traces,val1,val2="",condition='&'):

    start=time.perf_counter()
    
    key1=""
    key2=""

    values1=[]
    values2=[]

    if val1 in traces.values and val2 in traces.values:
        for key in traces.keys():
            if val1 in traces[key].values:
                if key1 != "":
                    choice=chooseValueIn(key1,key)
                    values1=traces[choice]
                    key1=choice
                else:
                    values1=traces[key]
                    key1=key
                            
            if val2 in trace[key].values:
                values2=traces[key]
                if key2 != "":
                    choice=chooseValueIn(key1,key)
                    values2=traces[choice]
                    key2=choice
                else:
                    values2=traces[key]
                    key2=key
   
    found=False
    decisionTime=time.time()
    index=0
    for i in values1:
        if condition=="&" and val2!="":
            if i==val1 and values2[index]==val2:
                found=True
                #return found,dict(traces.iloc[index])
                end = time.perf_counter()
                print("time of execution of the finally method (s) : {}".format(end-start))
                print()
                print(dict(traces.iloc[index]))
                return 1/(index+1), found
            index+=1
        elif condition=="|" and val2!="":
            if i==val1 or values2[index]==val2:
                found=True
                #return found,dict(traces.iloc[index])
                end = time.perf_counter()
                print("time of execution of the finally method (s) : {}".format(end-start))
                print()
                print(dict(traces.iloc[index]))
                return 1/(index+1), found
            index+=1
                    

    return found

#function which let the users decide if a value is contained in two columns 
def chooseValueIn(set,set2):
    choice=input("the value is present in both cols {} and {}, would you want to stay with the first col (Y/N):  ".format(set,set2))
    if choice.upper() == "Y":
        return set
    elif choice.upper()=="N":
        return set2

# implementation of the until algorith in a generic way by taking into parameter two values adapted to the context of the exercice
def untilAnomaly(traces,ip,labelStatus):
    start_time = time.time()
    
    key1=""
    key2=""

    values1=[]
    values2=[]

    if ip in traces.values and labelStatus in traces.values:
        for key in traces.keys():
            if ip in traces[key].values:
                if key1 != "":
                    choice=chooseValueIn(key1,key)
                    values1=traces[choice]
                    key1=choice
                else:
                    values1=traces[key]
                    key1=key
                            
            if labelStatus in trace[key].values:
                values2=traces[key]
                if key2 != "":
                    choice=chooseValueIn(key1,key)
                    values2=traces[choice]
                    key2=choice
                else:
                    values2=traces[key]
                    key2=key
        index=0
        decisionTime=time.time()

        for i in values1:
            if i==ip and values2[index]==labelStatus:
            
                end_time = time.time()
                print("time of  the execution of the until method at  : {} \n".format(end_time-start_time))

                return 1/(index+1),dict(traces.iloc[index]) 
            else:
                print(dict(traces.loc[index,:]))
                print()
                index+=1


#return the pandas dataframe with the column Timestamp and Flow_ID switched and the date from the Timestamp formated 
def traces(file,fullprint=False):
    swapColumns(file,"Flow_ID","Timestamp")

    timestamps=file["Timestamp"]
    traces={}
    
    for i in range(len(timestamps)):
        file.at[i,"Timestamp"]=file.at[i,"Timestamp"].split(" ")[0]

    file.sort_values(by=['Timestamp'], inplace=True)

    if fullprint:
        return file.to_string()

    return file
    


now=time.time()


newFile=swapColumns(file,"Flow_ID","Timestamp")

trace=traces(newFile)

print(untilAnomaly(newFile,"192.168.0.13","Anomaly"))


final=finallyAnomaly(newFile,"192.168.0.13","Anomaly")
print(final)
    

print("total execution Time : {}".format(time.time()-now))
