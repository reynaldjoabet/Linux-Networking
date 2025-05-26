#!/bin/bash

kubectl delete -f ../postgres-deployment.yaml --ignore-not-found=true
kubectl delete -f ../postgres-service.yaml --ignore-not-found=true

kubectl apply -f ../postgres-deployment.yaml
kubectl apply -f ../postgres-service.yaml