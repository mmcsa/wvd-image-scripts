#how-to-run AIB for WVD image build
#set var to name of image template to build

$imageTemp = "wvd-aib-o365-041006"

#deploy template
New-AzResourceGroupDeployment -ResourceGroupName $rg -TemplateFile .\AIB-WVD-template-1.json -imageTemplateName $imageTemp

#run action on image template to start Packer build
invoke-AzResourceAction -ResourceName $imageTemp -ResourceGroupName $rg -ResourceType "Microsoft.VirtualMachineImages/imageTemplates" -ApiVersion "2019-05-01-preview" -Action Run -Force
