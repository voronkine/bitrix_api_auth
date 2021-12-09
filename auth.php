class UsersAPIAuthorization {
	function AuthorizationAnswer() {
		$arResult = array();
		
		if(empty($_REQUEST['client_id']) || empty($_REQUEST['client_secret'])) {
			$arResult['category'] = 'DATA ERROR';
			$arResult['HTTP_status_code'] = '400 Bad Request';
			$arResult['description'] = 'Required parameters are missing in the request';
		} else {
			CModule::IncludeModule('highloadblock');
			$arUserData = array();
			$entity_data_class = GetEntityDataClass(USER_API_HL_ID);
			$rsData = $entity_data_class::getList(array(
			   'select' => array('*'),
			   'order' => array('ID' => 'ASC'),
			   'filter' => array('UF_USER_XML_ID' => $_REQUEST['client_id']),
			));
			if($el = $rsData->fetch()){
				$arUserData = $el;
			}
			if(!empty($arUserData)) {
				if($arUserData['UF_USER_SECRET'] == $_REQUEST['client_secret']) {
					$sTimestamp = time();
					$isUpdate = $entity_data_class::update($arUserData['ID'], array('UF_USER_TIME' => $sTimestamp));  
					if($isUpdate) {
						$sToken = md5($_REQUEST['client_id'] . $_SERVER['SERVER_SOFTWARE'] . $_REQUEST['client_secret'] . $sTimestamp);
						$arResult['category'] = 'SUCCESS';
						$arResult['HTTP_status_code'] = '200 OK';
						$arResult['access_token'] = $sToken;
						$arResult['expires_in'] = '600';
					} else {
						$arResult['category'] = 'SYSTEM ERROR';
						$arResult['HTTP_status_code'] = '500 Internal Server Error';
						$arResult['description'] = 'An unexpected server-side error occurred';
					}
				} else {
					$arResult['category'] = 'DATA ERROR';
					$arResult['HTTP_status_code'] = '400 Bad Request';
					$arResult['description'] = 'Client_secret is not valid';
				}
			} else {
				$arResult['category'] = 'DATA ERROR';
				$arResult['HTTP_status_code'] = '400 Bad Request';
				$arResult['description'] = 'User with requested Client_id is not found';
			}
		}
		return json_encode($arResult);
	}
	
	function CheckToken() {	
		$arResult = array();
		if(!empty($_SERVER['REMOTE_USER'])) {
			$sToken = $_SERVER['REMOTE_USER'];
			$sToken = str_replace('Bearer ', '', $sToken);
			if(!empty($sToken)) {
				CModule::IncludeModule('highloadblock');
				$arUserData = array();
				$entity_data_class = GetEntityDataClass(USER_API_HL_ID);
				$rsData = $entity_data_class::getList(array(
				   'select' => array('*'),
				   'order' => array('ID' => 'ASC'),
				   'filter' => array('UF_USER_ENDPOINT' => $_SERVER['SCRIPT_URL']),
				));
				if($el = $rsData->fetch()){
					$arUserData = $el;
				}
				$sCkeckToken = md5($arUserData['UF_USER_XML_ID'] . $_SERVER['SERVER_SOFTWARE'] . $arUserData['UF_USER_SECRET'] . $arUserData['UF_USER_TIME']);
				if($sCkeckToken == $sToken) {
					$arResult['category'] = 'SUCCESS';
					$arResult['HTTP_status_code'] = '200 OK';
				} else {
					$arResult['category'] = 'ERROR';
					$arResult['HTTP_status_code'] = '401 Unauthorized';
					$arResult['description'] = 'Access token is not valid';
				}
			} else {
				$arResult['category'] = 'ERROR';
				$arResult['HTTP_status_code'] = '401 Unauthorized';
				$arResult['description'] = 'Access token is not valid';
			}
			
		} else {
			$arResult['category'] = 'ERROR';
			$arResult['HTTP_status_code'] = '401 Unauthorized';
			$arResult['description'] = 'Missing access token';
		}
		return $arResult;
	}
}
