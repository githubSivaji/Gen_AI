import streamlit as st
import pandas as pd

st.title("stramlit text input")

name=st.text_input("Enter your name")

age=st.slider("select your age:",0,100,25)
st.write(f"your age is {age}")

options=["python","Java","C++","Javascript"]
choice=st.selectbox("choose your favourite language",options)
st.write(f"You Selected {choice}")

if name:
    st.write(f"hello ,{name}")

data ={
    "Name":["john","jane","Jake","Jill"],
    "Age":[28,24,35,40],
    "City":["New york","los angeles","chicago","Houston"]
}
df=pd.DataFrame(data)
df.to_csv("Sampledata.csv")
st.write(df)

uploaded_file=st.file_uploader("Choose a csv file",type="csv")
if uploaded_file is not None:
    df=pd.read_csv(uploaded_file)
    st.write(df)