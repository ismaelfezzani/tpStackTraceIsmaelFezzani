import time
import pandas as pd


file = pd.read_csv("Iot NetWork Intrusion Dataset.csv")


def chooseValueIn(set,set2):
    choice=input("the value is present in both cols {} and {}, would you want to stay with the first col (Y/N):  ".format(set,set2))
    if choice.upper() == "Y":
        return set
    elif choice.upper()=="N":
        return set2



def finallyAnomaly(traces,val,val2="",condition='&'):

    start=time.perf_counter()
    
    key1=""
    key2=""

    values1=[]
    values2=[]

    if val in traces.values and val2 in traces.values:
        for key in traces.keys():
            if val in traces[key].values:
                if key1 != "":
                    choice=chooseValueIn(key1,key)
                    values1=traces[choice]
                    key1=choice
                else:
                    values1=traces[key]
                    key1=key
                            
            if val2 in traces[key].values:
                values2=traces[key]
                if key2 != "":
                    choice=chooseValueIn(key1,key)
                    values2=traces[choice]
                    key2=choice
                else:
                    values2=traces[key]
                    key2=key
   
    found=False

    index=0
    for i in values1:
        if condition=="&" and val2!="":
            if i==val and values2[index]==val2:
                found=True
                #return found,dict(traces.iloc[index])
                end = time.perf_counter()
                print("time of execution of the finally method (s) : {}".format(end-start))
                print()
                return 1/(index+1), dict(traces.iloc[index])
            index+=1
        elif condition=="|" and val2!="":
            if i==val or values2[index]==val2:
                found=True
                #return found,dict(traces.iloc[index])
                end = time.perf_counter()
                print("time of execution of the finally method (s) : {}".format(end-start))
                print()
                return 1/(index+1), dict(traces.iloc[index])
            index+=1             

    return found



def globally(traces,val,val2):
    start=time.perf_counter()
    
    key1=""
    key2=""

    values1=[]
    values2=[]

    if val in traces.values and val2 in traces.values:
        for key in traces.keys():
            if val in traces[key].values:
                if key1 != "":
                    choice=chooseValueIn(key1,key)
                    values1=traces[choice]
                    key1=choice
                else:
                    values1=traces[key]
                    key1=key
                            
            if val2 in traces[key].values:
                values2=traces[key]
                if key2 != "":
                    choice=chooseValueIn(key1,key)
                    values2=traces[choice]
                    key2=choice
                else:
                    values2=traces[key]
                    key2=key
   
    found=False

    index=0
    nbLabel=0
    for i in values1:        
        if i==val and values2[index]==val2:
            found=True
                #return found,dict(traces.iloc[index])
            
            index+=1
            nbLabel+=1
        elif i!=val and values2[index]==val2:
            nbLabel+=1

    end = time.perf_counter()
    print("time of execution of the finally method (s) : {}".format(end-start))
    print(index)

    return index/nbLabel


print(globally(file,"192.168.0.13","Anomaly"))
print(finallyAnomaly(file,"192.168.0.13","Anomaly"))

