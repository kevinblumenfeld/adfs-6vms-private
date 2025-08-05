# Kevin adfs-6vms-regular-template-based

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fkevinblumenfeld%2Fadfs-6vms-private%2Fmain%2Fazuredeploy.json)
[![Visualize](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/visualizebutton.svg?sanitize=true)](http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fkevinblumenfeld%2Fadfs-6vms-private%2Fmain%2Fazuredeploy.json)

```PowerShell
New-AzResourceGroup -Name "KevinLab2" -Location "East US"

New-AzResourceGroupDeployment -ResourceGroupName "KevinLab2" -TemplateUri "https://raw.githubusercontent.com/kevinblumenfeld/adfs-6vms-private/main/azuredeploy.json" -Location "East US" -TemplateParameterObject @{ adminUsername = 'kevin'; adminPassword = '<**********************>' }
```
