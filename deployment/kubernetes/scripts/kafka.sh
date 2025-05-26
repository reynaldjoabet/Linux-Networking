#!/bin/bash

kubectl delete -f ../kafka-deployment.yaml --ignore-not-found=true
kubectl delete -f ../kafka-service.yaml --ignore-not-found=true

kubectl apply -f ../kafka-deployment.yaml
kubectl apply -f ../kafka-service.yaml